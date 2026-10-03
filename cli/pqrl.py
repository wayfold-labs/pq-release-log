#!/usr/bin/env python3
"""Build, sign, and simulate PQ Release Log releases."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request

from slhdsa import KeyPair, SecretKey, sha2_128s


CONFIG = {
    "registry": "<REGISTRY_ADDRESS>",  # Replace once, after the one-time deployment.
    "rpc": "https://rpc.mainnet.arc.io",
    "chain_id": 5042,
}
PRECOMPILE = "0x1800000000000000000000000000000000000004"
VERIFY_SELECTOR = bytes.fromhex("bf4db8ba")
REGISTER_DOMAIN = b"PQRL-REGISTER-v1"
PUBLISH_DOMAIN = b"PQRL-PUBLISH-v1"
NAME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")
ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

_RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
_ROT = ((0, 36, 3, 41, 18), (1, 44, 10, 45, 2), (62, 6, 43, 15, 61),
        (28, 55, 25, 21, 56), (27, 20, 39, 8, 14))
_MASK64 = (1 << 64) - 1


def _rotl(value: int, count: int) -> int:
    return value if count == 0 else ((value << count) | (value >> (64 - count))) & _MASK64


def _keccak_f(a: list[int]) -> None:
    for rc in _RC:
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x + 5 * y] ^= d[x]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl(a[x + 5 * y], _ROT[x][y])
        for x in range(5):
            for y in range(5):
                a[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
        a[0] ^= rc


def keccak256(data: bytes) -> bytes:
    padded = bytearray(data)
    padded.append(0x01)
    padded.extend(b"\0" * ((-len(padded)) % 136))
    padded[-1] |= 0x80
    state = [0] * 25
    for offset in range(0, len(padded), 136):
        block = padded[offset:offset + 136]
        for i in range(17):
            state[i] ^= int.from_bytes(block[i * 8:i * 8 + 8], "little")
        _keccak_f(state)
    return b"".join(x.to_bytes(8, "little") for x in state)[:32]


def parse_hex(value: str, length: int | None = None, label: str = "hex value") -> bytes:
    raw = value[2:] if value.startswith("0x") else value
    try:
        result = bytes.fromhex(raw)
    except ValueError as exc:
        raise ValueError(f"invalid {label}") from exc
    if length is not None and len(result) != length:
        raise ValueError(f"{label} must be exactly {length} bytes")
    return result


def parse_address(value: str) -> bytes:
    if not ADDRESS_RE.fullmatch(value):
        raise ValueError("address must be 0x followed by 40 hexadecimal characters")
    body = value[2:]
    if body != body.lower():
        lower = body.lower()
        digest = keccak256(lower.encode("ascii")).hex()
        checksummed = "".join(
            c.upper() if c in "abcdef" and int(digest[i], 16) >= 8 else c
            for i, c in enumerate(lower)
        )
        if body != checksummed:
            raise ValueError("address must be lowercase or have a valid EIP-55 checksum")
    return bytes.fromhex(body)


def uint(value: int, size: int) -> bytes:
    if value < 0 or value >= 1 << (size * 8):
        raise ValueError(f"integer does not fit in uint{size * 8}")
    return value.to_bytes(size, "big")


def validate_name(name: str) -> None:
    raw = name.encode("utf-8")
    if not 1 <= len(raw) <= 64 or any(c not in NAME_CHARS for c in name):
        raise ValueError("name must be 1-64 bytes using only [a-z0-9-]")


def project_key(owner: str, name: str) -> bytes:
    validate_name(name)
    raw = name.encode()
    # abi.encode(address,string): two heads, then string length and padded bytes.
    encoded = parse_address(owner).rjust(32, b"\0") + uint(64, 32) + uint(len(raw), 32) + _pad32(raw)
    return keccak256(encoded)


def register_message(chain_id: int, registry: str, key: str, owner: str, vk: bytes) -> bytes:
    return b"".join((REGISTER_DOMAIN, uint(chain_id, 32), parse_address(registry),
                     parse_hex(key, 32, "project key"), parse_address(owner), vk))


def publish_message(chain_id: int, registry: str, key: str, seq: int, manifest_hash: bytes, uri: str) -> bytes:
    return b"".join((PUBLISH_DOMAIN, uint(chain_id, 32), parse_address(registry),
                     parse_hex(key, 32, "project key"), uint(seq, 8), manifest_hash,
                     keccak256(uri.encode("utf-8"))))


def load_key(path: str) -> SecretKey:
    key_path = Path(path)
    mode = stat.S_IMODE(key_path.stat().st_mode)
    if mode != 0o600:
        raise ValueError(f"refusing key file with permissions {mode:o}; require exactly 0600")
    document = json.loads(key_path.read_text(encoding="utf-8"))
    if document.get("algorithm") != "SLH-DSA-SHA2-128s":
        raise ValueError("unsupported key algorithm")
    return SecretKey.from_digest(parse_hex(document["secret_key"], 64, "secret key"), sha2_128s)


def write_key(path: str) -> bytes:
    key_path = Path(path)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    keypair = KeyPair.gen(sha2_128s)
    document = {"algorithm": "SLH-DSA-SHA2-128s", "verification_key": "0x" + keypair.pub.digest().hex(),
                "secret_key": "0x" + keypair.sec.digest().hex()}
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")
    return keypair.pub.digest()


def _canonical(document: dict[str, object]) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def manifest(directory: str, output: str, site: str | None = None, generated_at: str | None = None) -> dict[str, object]:
    if site is None:
        raise ValueError("DIR mode requires --site https://...")
    parsed_site = urllib.parse.urlparse(site)
    if parsed_site.scheme != "https" or not parsed_site.netloc:
        raise ValueError("--site must be an https:// URL")
    root = Path(directory).resolve(strict=True)
    output_path = Path(output).resolve()
    files: dict[str, str] = {}
    for path in sorted((p for p in root.rglob("*") if p.is_file()), key=lambda p: p.relative_to(root).as_posix()):
        relative = path.relative_to(root)
        if any(part.startswith(".") for part in relative.parts):
            continue
        if path.resolve() == output_path:
            continue
        if path.is_symlink():
            raise ValueError(f"refusing symlink: {relative}")
        files[relative.as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    if not files:
        raise ValueError("manifest file list is empty")
    document: dict[str, object] = {"version": 1, "site": site, "files": files,
                                  "generated_at": generated_at or _iso_now()}
    Path(output).write_bytes(_canonical(document))
    return document


def live_manifest(base_url: str, names: list[str], output: str) -> dict[str, object]:
    if not names:
        raise ValueError("--files must list at least one file")
    base = base_url.rstrip("/") + "/"
    files: dict[str, str] = {}
    for name in sorted(set(names)):
        if name.startswith("/") or ".." in Path(name).parts or "\\" in name:
            raise ValueError(f"unsafe file path: {name}")
        request = urllib.request.Request(urllib.parse.urljoin(base, name), headers={"cache-control": "no-cache"})
        with urllib.request.urlopen(request, timeout=60) as response:
            files[name] = hashlib.sha256(response.read()).hexdigest()
    document: dict[str, object] = {"version": 1, "site": base_url, "files": files, "generated_at": _iso_now()}
    Path(output).write_bytes(_canonical(document))
    return document


def _pad32(data: bytes) -> bytes:
    return data + b"\0" * ((-len(data)) % 32)


def _dynamic(data: bytes) -> bytes:
    return uint(len(data), 32) + _pad32(data)


def encode_verify_call(vk: bytes, message: bytes, signature: bytes) -> bytes:
    tails = [_dynamic(v) for v in (vk, message, signature)]
    offsets, offset = [], 96
    for tail in tails:
        offsets.append(uint(offset, 32)); offset += len(tail)
    return VERIFY_SELECTOR + b"".join(offsets + tails)


def encode_publish_call(key: bytes, seq: int, manifest_hash: bytes, uri: str, signature: bytes) -> bytes:
    selector = keccak256(b"publish(bytes32,uint64,bytes32,string,bytes)")[:4]
    uri_tail, sig_tail = _dynamic(uri.encode()), _dynamic(signature)
    return b"".join((selector, key, uint(seq, 32), manifest_hash, uint(160, 32),
                     uint(160 + len(uri_tail), 32), uri_tail, sig_tail))


def encode_register_call(name: str, vk: bytes, signature: bytes) -> bytes:
    selector = keccak256(b"registerProject(string,bytes,bytes)")[:4]
    tails = [_dynamic(name.encode()), _dynamic(vk), _dynamic(signature)]
    offsets: list[bytes] = []
    offset = 96
    for tail in tails:
        offsets.append(uint(offset, 32))
        offset += len(tail)
    return selector + b"".join(offsets + tails)


def encode_single_bytes32_call(signature: bytes, value: bytes) -> bytes:
    return keccak256(signature)[:4] + value


def _rpc_bytes(value: object, label: str) -> bytes:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise RuntimeError(f"malformed {label} RPC response")
    return parse_hex(value, label=label)


def _word_at(raw: bytes, index: int) -> int:
    start = index * 32
    if len(raw) < start + 32:
        raise RuntimeError("short ABI response")
    return int.from_bytes(raw[start:start + 32], "big")


def decode_project(value: object) -> tuple[str, bytes, int]:
    raw = _rpc_bytes(value, "project")
    owner = "0x" + _word_at(raw, 0).to_bytes(32, "big")[-20:].hex()
    offset = _word_at(raw, 1)
    latest_seq = _word_at(raw, 2)
    if offset + 32 > len(raw):
        raise RuntimeError("malformed project response")
    length = int.from_bytes(raw[offset:offset + 32], "big")
    vk = raw[offset + 32:offset + 32 + length]
    if len(vk) != length:
        raise RuntimeError("malformed project verification key")
    return owner, vk, latest_seq


def decode_release(value: object) -> tuple[bytes, str, int, int]:
    raw = _rpc_bytes(value, "release")
    start = 32 if _word_at(raw, 0) == 32 else 0
    manifest_hash = raw[start:start + 32]
    uri_offset = int.from_bytes(raw[start + 32:start + 64], "big")
    block_number = int.from_bytes(raw[start + 64:start + 96], "big")
    timestamp = int.from_bytes(raw[start + 96:start + 128], "big")
    uri_start = start + uri_offset
    if uri_start + 32 > len(raw):
        raise RuntimeError("malformed release response")
    uri_length = int.from_bytes(raw[uri_start:uri_start + 32], "big")
    uri_raw = raw[uri_start + 32:uri_start + 32 + uri_length]
    if len(uri_raw) != uri_length:
        raise RuntimeError("malformed release URI")
    return manifest_hash, uri_raw.decode("utf-8"), block_number, timestamp


def rpc(rpc_url: str, method: str, params: list[object]) -> object:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(rpc_url, data=payload,
        headers={"content-type": "application/json", "user-agent": "pqrl-cli/2.0"})
    with urllib.request.urlopen(request, timeout=60) as response:
        result = json.load(response)
    if "error" in result:
        raise RuntimeError(f"RPC error: {result['error']}")
    return result["result"]


def check_network(rpc_url: str, registry: str, chain_id: int) -> None:
    actual_chain = int(str(rpc(rpc_url, "eth_chainId", [])), 16)
    if actual_chain != chain_id:
        raise RuntimeError(f"wrong chain id: expected {chain_id}, RPC returned {actual_chain}")
    code = rpc(rpc_url, "eth_getCode", [registry, "latest"])
    if not isinstance(code, str) or code == "0x" or not code.startswith("0x"):
        raise RuntimeError("registry has no code")


def precompile_check(rpc_url: str, vk: bytes, message: bytes, signature: bytes) -> None:
    verify_data = "0x" + encode_verify_call(vk, message, signature).hex()
    verified = rpc(rpc_url, "eth_call", [{"to": PRECOMPILE, "data": verify_data}, "latest"])
    if verified != "0x" + "0" * 63 + "1":
        raise RuntimeError(f"precompile rejected signature: {verified}")


def cast_command(arguments: list[str]) -> str:
    return shlex.join(arguments)


def command_keygen(args: argparse.Namespace) -> None:
    vk = write_key(args.out)
    print(f"created {args.out} (0600)")
    print("verification_key=0x" + vk.hex())


def command_manifest(args: argparse.Namespace) -> None:
    if args.base_url:
        document = live_manifest(args.base_url, [x for x in args.files.split(",") if x], args.out)
    else:
        document = manifest(args.directory, args.out, args.site)
    raw = Path(args.out).read_bytes()
    print(f"wrote {len(document['files'])} files to {args.out}")
    for name in document["files"]:
        print(f"file={name}")
    print("manifest_hash=0x" + hashlib.sha256(raw).hexdigest())


def command_sign_register(args: argparse.Namespace) -> None:
    registry = args.registry
    if registry == "<REGISTRY_ADDRESS>":
        raise ValueError("registry is still <REGISTRY_ADDRESS>")
    secret = load_key(args.key)
    key = project_key(args.owner, args.name)
    message = register_message(args.chain_id, registry, "0x" + key.hex(), args.owner, secret.pubkey.digest())
    signature = secret.sign_pure(message, randomize=True, ctx=b"")
    print("project_key=0x" + key.hex())
    print("message=0x" + message.hex())
    print("signature=0x" + signature.hex())


def command_register_plan(args: argparse.Namespace) -> None:
    registry = args.registry
    if registry == "<REGISTRY_ADDRESS>":
        raise ValueError("registry is still <REGISTRY_ADDRESS>")
    parse_address(registry)
    parse_address(args.owner)
    check_network(args.rpc, registry, args.chain_id)
    secret = load_key(args.key)
    vk = secret.pubkey.digest()
    key = project_key(args.owner, args.name)
    message = register_message(args.chain_id, registry, "0x" + key.hex(), args.owner, vk)
    signature = (parse_hex(Path(args.signature_in).read_text(encoding="ascii").strip(), 7856, "signature")
                 if args.signature_in else secret.sign_pure(message, randomize=True, ctx=b""))
    precompile_check(args.rpc, vk, message, signature)
    calldata = "0x" + encode_register_call(args.name, vk, signature).hex()
    rpc(args.rpc, "eth_call", [{"from": args.owner, "to": registry, "data": calldata}, "latest"])
    print("project_key=0x" + key.hex())
    print("verification_key=0x" + vk.hex())
    print("precompile_check=VALID")
    print("register_eth_call=SUCCESS")
    print(cast_command([
        "cast", "send", "--rpc-url", args.rpc, "--account", "<KEYSTORE>", registry,
        "registerProject(string,bytes,bytes)", args.name, "0x" + vk.hex(), "0x" + signature.hex(),
    ]))


def command_publish_plan(args: argparse.Namespace) -> None:
    registry = args.registry
    if registry == "<REGISTRY_ADDRESS>":
        raise ValueError("registry is still <REGISTRY_ADDRESS>")
    parse_address(registry)
    parse_address(args.owner)
    check_network(args.rpc, registry, args.chain_id)
    secret = load_key(args.key)
    vk = secret.pubkey.digest()
    manifest_hash = hashlib.sha256(Path(args.manifest).read_bytes()).digest()
    key = project_key(args.owner, args.name)
    project_data = "0x" + encode_single_bytes32_call(b"project(bytes32)", key).hex()
    project_owner, project_vk, latest_seq = decode_project(
        rpc(args.rpc, "eth_call", [{"to": registry, "data": project_data}, "latest"])
    )
    if project_owner.lower() != args.owner.lower():
        raise RuntimeError(f"project owner mismatch: chain has {project_owner}")
    if project_vk != vk:
        raise RuntimeError("project verification key does not match --key")
    if latest_seq + 1 != args.seq:
        raise RuntimeError(f"wrong sequence: expected {latest_seq + 1}, supplied {args.seq}")
    message = publish_message(args.chain_id, registry, "0x" + key.hex(), args.seq, manifest_hash, args.uri)
    signature = (parse_hex(Path(args.signature_in).read_text(encoding="ascii").strip(), 7856, "signature")
                 if args.signature_in else secret.sign_pure(message, randomize=True, ctx=b""))
    precompile_check(args.rpc, vk, message, signature)
    calldata = "0x" + encode_publish_call(key, args.seq, manifest_hash, args.uri, signature).hex()
    rpc(args.rpc, "eth_call", [{"from": args.owner, "to": registry, "data": calldata}, "latest"])
    sig_path = Path(args.signature_out or (args.manifest + f".{args.seq}.sig"))
    sig_path.write_text("0x" + signature.hex() + "\n", encoding="ascii")
    print("project_key=0x" + key.hex())
    print("manifest_hash=0x" + manifest_hash.hex())
    print("message=0x" + message.hex())
    print(f"signature_file={sig_path}")
    print("precompile_check=VALID")
    print("publish_eth_call=SUCCESS")
    print(cast_command([
        "cast", "send", "--rpc-url", args.rpc, "--account", "<KEYSTORE>", registry,
        "publish(bytes32,uint64,bytes32,string,bytes)", "0x" + key.hex(), str(args.seq),
        "0x" + manifest_hash.hex(), args.uri, "0x" + signature.hex(),
    ]))


def _fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"cache-control": "no-cache", "user-agent": "pqrl-cli/2.0"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def command_verify_site(args: argparse.Namespace) -> None:
    registry = args.registry
    if registry == "<REGISTRY_ADDRESS>":
        raise ValueError("registry is still <REGISTRY_ADDRESS>")
    parse_address(registry)
    parse_address(args.owner)
    validate_name(args.name)
    parsed_site = urllib.parse.urlparse(args.site)
    if parsed_site.scheme != "https" or not parsed_site.netloc:
        raise ValueError("--site must be an https:// URL")
    check_network(args.rpc, registry, args.chain_id)
    key = project_key(args.owner, args.name)
    project_data = "0x" + encode_single_bytes32_call(b"project(bytes32)", key).hex()
    project_owner, vk, seq = decode_project(
        rpc(args.rpc, "eth_call", [{"to": registry, "data": project_data}, "latest"])
    )
    if project_owner == "0x" + "0" * 40 or seq == 0:
        raise RuntimeError("project is unregistered or has no releases")
    if project_owner.lower() != args.owner.lower() or len(vk) != 32:
        raise RuntimeError("project response does not match the requested owner")
    release_data = "0x" + (
        keccak256(b"release(bytes32,uint64)")[:4] + key + uint(seq, 32)
    ).hex()
    manifest_hash, uri, block_number, timestamp = decode_release(
        rpc(args.rpc, "eth_call", [{"to": registry, "data": release_data}, "latest"])
    )
    registration_data = "0x" + encode_single_bytes32_call(b"registrationBlockFor(bytes32)", key).hex()
    registration_raw = _rpc_bytes(
        rpc(args.rpc, "eth_call", [{"to": registry, "data": registration_data}, "latest"]), "registration block"
    )
    registration_block = _word_at(registration_raw, 0)
    parsed_uri = urllib.parse.urlparse(uri)
    if parsed_uri.scheme != "https" or not parsed_uri.netloc:
        raise RuntimeError("on-chain manifest URI is not HTTPS")
    manifest_raw = _fetch(uri)
    if hashlib.sha256(manifest_raw).digest() != manifest_hash:
        raise RuntimeError("manifest does not match the chain")
    document = json.loads(manifest_raw)
    files = document.get("files") if isinstance(document, dict) else None
    if not isinstance(files, dict) or not files:
        raise RuntimeError("manifest files must be a non-empty object")
    base = args.site.rstrip("/") + "/"
    failures: list[str] = []
    for name, wanted in sorted(files.items()):
        if (not isinstance(name, str) or name.startswith(("/", "//")) or ".." in Path(name).parts
                or any(c in name for c in "\\:?#") or not isinstance(wanted, str)
                or not re.fullmatch(r"[0-9a-f]{64}", wanted)):
            raise RuntimeError(f"invalid manifest entry: {name!r}")
        try:
            actual = hashlib.sha256(_fetch(urllib.parse.urljoin(base, name))).hexdigest()
        except (OSError, urllib.error.URLError):
            failures.append(name)
            continue
        if actual != wanted:
            failures.append(name)
    print(f"registry={registry}")
    print(f"rpc={args.rpc}")
    print(f"owner={args.owner}")
    print(f"name={args.name}")
    print(f"site={base}")
    print(f"manifest_site={document.get('site')}")
    print(f"release_seq={seq}")
    print(f"release_block={block_number}")
    print(f"registration_block={registration_block}")
    print(f"release_timestamp={timestamp}")
    print("vk_fingerprint=0x" + keccak256(vk).hex())
    print(f"files_checked={len(files)}")
    manifest_site = document.get("site")
    if manifest_site != base:
        print(f"WARNING: manifest.site differs from checked site: {manifest_site!r}")
    if failures:
        raise RuntimeError("changed or missing files: " + ", ".join(failures))
    print("VERIFIED")


def command_verify(args: argparse.Namespace) -> None:
    vk = load_key(args.key).pubkey.digest() if args.key else parse_hex(args.vk, 32, "verification key")
    data = "0x" + encode_verify_call(vk, parse_hex(args.message), parse_hex(args.signature, 7856, "signature")).hex()
    result = rpc(args.rpc, "eth_call", [{"to": PRECOMPILE, "data": data}, "latest"])
    if result == "0x" + "0" * 63 + "1":
        print("VALID"); return
    if result == "0x" + "0" * 64:
        print("INVALID"); raise SystemExit(1)
    raise RuntimeError(f"malformed precompile response: {result}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    keygen = commands.add_parser("keygen"); keygen.add_argument("--out", required=True); keygen.set_defaults(func=command_keygen)
    make = commands.add_parser("manifest")
    make.add_argument("directory", nargs="?"); make.add_argument("--base-url"); make.add_argument("--files")
    make.add_argument("--site"); make.add_argument("--out", default="manifest.json"); make.set_defaults(func=command_manifest)
    register = commands.add_parser("sign-register")
    register.add_argument("--key", required=True); register.add_argument("--owner", required=True)
    register.add_argument("--name", required=True); register.add_argument("--registry", default=CONFIG["registry"])
    register.add_argument("--chain-id", type=int, default=CONFIG["chain_id"]); register.set_defaults(func=command_sign_register)
    register_plan = commands.add_parser("register-plan")
    register_plan.add_argument("--key", required=True); register_plan.add_argument("--owner", required=True)
    register_plan.add_argument("--name", required=True); register_plan.add_argument("--registry", default=CONFIG["registry"])
    register_plan.add_argument("--signature-in", help=argparse.SUPPRESS)
    register_plan.add_argument("--chain-id", type=int, default=CONFIG["chain_id"])
    register_plan.add_argument("--rpc", default=CONFIG["rpc"]); register_plan.set_defaults(func=command_register_plan)
    publish = commands.add_parser("publish-plan")
    publish.add_argument("--key", required=True); publish.add_argument("--owner", required=True)
    publish.add_argument("--name", required=True); publish.add_argument("--seq", required=True, type=int)
    publish.add_argument("--manifest", required=True); publish.add_argument("--uri", required=True)
    publish.add_argument("--signature-out"); publish.add_argument("--signature-in")
    publish.add_argument("--registry", default=CONFIG["registry"])
    publish.add_argument("--chain-id", type=int, default=CONFIG["chain_id"]); publish.add_argument("--rpc", default=CONFIG["rpc"])
    publish.set_defaults(func=command_publish_plan)
    verify = commands.add_parser("verify-onchain")
    source = verify.add_mutually_exclusive_group(required=True); source.add_argument("--key"); source.add_argument("--vk")
    verify.add_argument("--message", required=True); verify.add_argument("--signature", required=True)
    verify.add_argument("--rpc", default=CONFIG["rpc"]); verify.set_defaults(func=command_verify)
    verify_site = commands.add_parser("verify-site")
    verify_site.add_argument("--owner", required=True); verify_site.add_argument("--name", required=True)
    verify_site.add_argument("--site", required=True); verify_site.add_argument("--registry", default=CONFIG["registry"])
    verify_site.add_argument("--chain-id", type=int, default=CONFIG["chain_id"])
    verify_site.add_argument("--rpc", default=CONFIG["rpc"]); verify_site.set_defaults(func=command_verify_site)
    return parser


def main() -> None:
    try:
        args = build_parser().parse_args()
        if args.command == "manifest" and bool(args.base_url) != bool(args.files):
            raise ValueError("live manifest requires both --base-url and --files")
        if args.command == "manifest" and not args.base_url and not args.directory:
            raise ValueError("manifest requires DIR or --base-url/--files")
        args.func(args)
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr); raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
