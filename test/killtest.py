#!/usr/bin/env python3
"""Read-only Arc mainnet gate using eth_call state overrides."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "cli"))

from pqrl import (  # noqa: E402
    encode_publish_call,
    encode_register_call,
    keccak256,
    manifest,
    parse_address,
    project_key,
    publish_message,
    register_message,
    rpc,
    uint,
    write_key,
    load_key,
)


RPC_URL = os.environ.get("ARC_RPC_URL", "https://rpc.mainnet.arc.io")
CHAIN_ID = 5042
REGISTRY = "0x00000000000000000000000000000000a11ce001"
HARNESS = "0x00000000000000000000000000000000a11ce002"
OTHER_REGISTRY = "0x00000000000000000000000000000000a11ce003"
CALLER = "0x0000000000000000000000000000000000000001"
PROJECT_NAME = "paylink-killtest"
URI = "https://wayfold-labs.github.io/arc-miniapp/manifest.json"
INVALID_RELEASE_SIGNATURE = "0xcda44837"
INVALID_PROOF_OF_POSSESSION = "0x92536faf"


def pad32(value: bytes) -> bytes:
    return value + b"\0" * ((-len(value)) % 32)


def dynamic(value: bytes) -> bytes:
    return uint(len(value), 32) + pad32(value)


def encode_run(
    registry: str,
    vk: bytes,
    pop_sig: bytes,
    seq: int,
    manifest_hash: bytes,
    uri: str,
    signature: bytes,
) -> bytes:
    selector = keccak256(b"run(address,bytes,bytes,uint64,bytes32,string,bytes)")[:4]
    values: list[tuple[bool, bytes]] = [
        (False, parse_address(registry).rjust(32, b"\0")),
        (True, vk),
        (True, pop_sig),
        (False, uint(seq, 32)),
        (False, manifest_hash),
        (True, uri.encode()),
        (True, signature),
    ]
    offset = 32 * len(values)
    heads: list[bytes] = []
    tails: list[bytes] = []
    for is_dynamic, value in values:
        if not is_dynamic:
            heads.append(value)
            continue
        encoded = dynamic(value)
        heads.append(uint(offset, 32))
        tails.append(encoded)
        offset += len(encoded)
    return selector + b"".join(heads + tails)


def encode_publish(project_id: bytes, manifest_hash: bytes, uri: str, signature: bytes) -> bytes:
    selector = keccak256(b"publish(bytes32,uint64,bytes32,string,bytes)")[:4]
    uri_encoded = dynamic(uri.encode())
    sig_encoded = dynamic(signature)
    head_size = 5 * 32
    return b"".join((
        selector,
        project_id,
        uint(1, 32),
        manifest_hash,
        uint(head_size, 32),
        uint(head_size + len(uri_encoded), 32),
        uri_encoded,
        sig_encoded,
    ))


def load_runtime(contract: str) -> str:
    artifact = ROOT / "out" / f"{contract}.sol" / f"{contract}.json"
    data = json.loads(artifact.read_text())
    bytecode = data["deployedBytecode"]["object"]
    return bytecode if bytecode.startswith("0x") else "0x" + bytecode


def rpc_document(method: str, params: list[object]) -> dict[str, object]:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(
        RPC_URL, data=payload, headers={"content-type": "application/json", "user-agent": "pqrl-killtest/2.0"}
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def _revert_data(value: object) -> str | None:
    if isinstance(value, str) and value.startswith("0x"):
        return value
    if isinstance(value, dict):
        for key in ("data", "result", "error"):
            found = _revert_data(value.get(key))
            if found is not None:
                return found
    return None


def expect_revert_selector(call: dict[str, str], overrides: dict[str, object], selector: str) -> bool:
    document = rpc_document("eth_call", [call, "latest", overrides])
    data = _revert_data(document.get("error"))
    if data != selector:
        print(f"FAIL: expected revert data {selector}, got {data!r}: {document.get('error')}")
        return False
    return True


def storage_word(value: int) -> str:
    return "0x" + value.to_bytes(32, "big").hex()


def registered_project_state(key: bytes, owner: str, vk: bytes, latest_seq: int = 0) -> dict[str, str]:
    base = int.from_bytes(keccak256(key + uint(0, 32)), "big")
    vk_slot = base + 1
    return {
        storage_word(base): "0x" + parse_address(owner).rjust(32, b"\0").hex(),
        storage_word(vk_slot): storage_word(65),
        "0x" + keccak256(uint(vk_slot, 32)).hex(): "0x" + vk.hex(),
        storage_word(base + 2): storage_word(latest_seq),
    }


def main() -> int:
    print("PQRL kill test: Arc mainnet, read-only state overrides")
    chain = int(str(rpc(RPC_URL, "eth_chainId", [])), 16)
    if chain != CHAIN_ID:
        print(f"FAIL: expected chain {CHAIN_ID}, RPC returned {chain}")
        return 1
    for address in (REGISTRY, HARNESS, OTHER_REGISTRY):
        if rpc(RPC_URL, "eth_getCode", [address, "latest"]) != "0x":
            print(f"FAIL: state-override address is not unused: {address}")
            return 1

    with tempfile.TemporaryDirectory(prefix="pqrl-killtest-") as temporary:
        tmp = Path(temporary)
        site = tmp / "paylink"
        site.mkdir()
        with urllib.request.urlopen("https://wayfold-labs.github.io/arc-miniapp/", timeout=60) as response:
            index = response.read()
        (site / "index.html").write_bytes(index)
        manifest_path = tmp / "manifest.json"
        manifest(str(site), str(manifest_path), "https://wayfold-labs.github.io/arc-miniapp/")
        manifest_hash = hashlib.sha256(manifest_path.read_bytes()).digest()

        key_path = tmp / "killtest.key"
        vk = write_key(str(key_path))
        secret = load_key(str(key_path))
        project_key_value = project_key(HARNESS, PROJECT_NAME)
        pop_message = register_message(CHAIN_ID, REGISTRY, "0x" + project_key_value.hex(), HARNESS, vk)
        pop_sig = secret.sign_pure(pop_message, randomize=True, ctx=b"")
        release_message = publish_message(
            CHAIN_ID, REGISTRY, "0x" + project_key_value.hex(), 1, manifest_hash, URI
        )
        release_sig = secret.sign_pure(release_message, randomize=True, ctx=b"")
        wrong_registry_message = publish_message(
            CHAIN_ID, OTHER_REGISTRY, "0x" + project_key_value.hex(), 1, manifest_hash, URI
        )
        wrong_registry_sig = secret.sign_pure(wrong_registry_message, randomize=True, ctx=b"")

        overrides = {
            REGISTRY: {"code": load_runtime("PQReleaseLog")},
            HARNESS: {"code": load_runtime("KillTestHarness")},
        }
        good_data = encode_run(
            REGISTRY, vk, pop_sig, 1, manifest_hash, URI, release_sig
        )
        call = {"from": CALLER, "to": HARNESS, "data": "0x" + good_data.hex()}
        result = str(rpc(RPC_URL, "eth_call", [call, "latest", overrides]))
        if len(result) != 66:
            print(f"FAIL: successful combined call returned malformed data: {result}")
            return 1
        publish_gas = int(result, 16)

        tampered_hash = bytes([manifest_hash[0] ^ 1]) + manifest_hash[1:]
        tampered_call = dict(call)
        tampered_call["data"] = "0x" + encode_run(
            REGISTRY, vk, pop_sig, 1, tampered_hash, URI, release_sig
        ).hex()
        tampered_reverted = expect_revert_selector(tampered_call, overrides, INVALID_RELEASE_SIGNATURE)

        wrong_registry_call = dict(call)
        wrong_registry_call["data"] = "0x" + encode_run(
            REGISTRY, vk, pop_sig, 1, manifest_hash, URI, wrong_registry_sig
        ).hex()
        wrong_registry_reverted = expect_revert_selector(wrong_registry_call, overrides, INVALID_RELEASE_SIGNATURE)

        bad_pop = bytes([pop_sig[0] ^ 1]) + pop_sig[1:]
        bad_pop_call = dict(call)
        bad_pop_call["data"] = "0x" + encode_run(
            REGISTRY, vk, bad_pop, 1, manifest_hash, URI, release_sig
        ).hex()
        bad_pop_reverted = expect_revert_selector(bad_pop_call, overrides, INVALID_PROOF_OF_POSSESSION)

        estimate: int | None = None
        try:
            estimate = int(str(rpc(RPC_URL, "eth_estimateGas", [call, "latest", overrides])), 16)
        except RuntimeError as exc:
            print(f"eth_estimateGas combined call: unavailable ({exc})")

        eoa_key = project_key(CALLER, PROJECT_NAME)
        eoa_pop_message = register_message(CHAIN_ID, REGISTRY, "0x" + eoa_key.hex(), CALLER, vk)
        eoa_pop_sig = secret.sign_pure(eoa_pop_message, randomize=True, ctx=b"")
        register_calldata = encode_register_call(PROJECT_NAME, vk, eoa_pop_sig)
        register_estimate = int(str(rpc(RPC_URL, "eth_estimateGas", [{
            "from": CALLER, "to": REGISTRY, "data": "0x" + register_calldata.hex()
        }, "latest", {REGISTRY: {"code": load_runtime("PQReleaseLog")}}])), 16)

        eoa_release_message = publish_message(
            CHAIN_ID, REGISTRY, "0x" + eoa_key.hex(), 1, manifest_hash, URI
        )
        eoa_release_sig = secret.sign_pure(eoa_release_message, randomize=True, ctx=b"")
        publish_calldata = encode_publish_call(eoa_key, 1, manifest_hash, URI, eoa_release_sig)
        publish_overrides = {REGISTRY: {
            "code": load_runtime("PQReleaseLog"),
            "stateDiff": registered_project_state(eoa_key, CALLER, vk),
        }}
        publish_estimate = int(str(rpc(RPC_URL, "eth_estimateGas", [{
            "from": CALLER, "to": REGISTRY, "data": "0x" + publish_calldata.hex()
        }, "latest", publish_overrides])), 16)
        print(f"PayLink index.html bytes: {len(index)}")
        print(f"Manifest SHA-256: 0x{manifest_hash.hex()}")
        print(f"SLH-DSA verification key bytes: {len(vk)}; signature bytes: {len(release_sig)}")
        print(f"Combined register+publish eth_call: success")
        print(f"Tampered manifest hash: {'reverted' if tampered_reverted else 'DID NOT REVERT'}")
        print(f"Different-registry publish signature: {'reverted' if wrong_registry_reverted else 'DID NOT REVERT'}")
        print(f"Bad proof of possession: {'reverted' if bad_pop_reverted else 'DID NOT REVERT'}")
        print(f"Publish inner-execution gas measured by harness (excludes transaction/calldata): {publish_gas}")
        if estimate is not None:
            print(f"Combined call eth_estimateGas: {estimate}")
        print(f"Register-only EOA eth_estimateGas: {register_estimate}")
        print(f"Publish-only EOA eth_estimateGas with registered-project state override: {publish_estimate}")
        print(f"Publish calldata bytes: {len(publish_calldata)}")

        if tampered_reverted and wrong_registry_reverted and bad_pop_reverted and publish_estimate < 1_000_000:
            print("PASS")
            return 0
        print("FAIL: a negative case did not revert")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
