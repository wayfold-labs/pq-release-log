#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"
: "${CHROME:?CHROME must point to chrome-headless-shell}"
[[ -x .venv/bin/python ]] || { echo "FAIL: .venv is missing" >&2; exit 1; }

rpc_port=18545
web_port=18080
rpc="http://127.0.0.1:${rpc_port}"
base="http://127.0.0.1:${web_port}"
mainnet_rpc="${ARC_RPC_URL:-https://rpc.mainnet.arc.io}"
owner="0x3DF09eF258C7589508aD92b48896cE9763Df7231"
precompile="0x1800000000000000000000000000000000000004"
tmp="$(mktemp -d)"
anvil_pid=""
http_pid=""
cleanup() {
  [[ -z "$http_pid" ]] || kill "$http_pid" 2>/dev/null || true
  [[ -z "$anvil_pid" ]] || kill "$anvil_pid" 2>/dev/null || true
  if [[ "${KEEP_E2E_TMP:-0}" == 1 ]]; then echo "e2e artifacts: $tmp"; else rm -rf -- "$tmp"; fi
}
trap cleanup EXIT

anvil --silent --port "$rpc_port" --chain-id 5042 >"$tmp/anvil.log" 2>&1 &
anvil_pid=$!
for _ in {1..50}; do cast chain-id --rpc-url "$rpc" >/dev/null 2>&1 && break; sleep .1; done
[[ "$(cast chain-id --rpc-url "$rpc")" == 5042 ]]

table_runtime="$(.venv/bin/python - <<'PY'
import json
value=json.load(open('out/PQReleaseLog.t.sol/TablePQMock.json'))['deployedBytecode']['object']
print(value if value.startswith('0x') else '0x'+value)
PY
)"
cast rpc --rpc-url "$rpc" anvil_setCode "$precompile" "$table_runtime" >/dev/null
cast rpc --rpc-url "$rpc" anvil_impersonateAccount "$owner" >/dev/null
cast rpc --rpc-url "$rpc" anvil_setBalance "$owner" 0x56bc75e2d63100000 >/dev/null
deploy="$(forge create src/PQReleaseLog.sol:PQReleaseLog --broadcast --unlocked --from "$owner" --rpc-url "$rpc")"
registry="$(printf '%s\n' "$deploy" | sed -n 's/^Deployed to: //p')"
[[ "$registry" =~ ^0x[0-9a-fA-F]{40}$ ]]

mkdir -p "$tmp/web/site" "$tmp/web/verifier"
cp -R docs/. "$tmp/web/verifier/"
printf '%s\n' '<!doctype html><title>Real release</title><h1>Authentic</h1>' >"$tmp/web/site/index.html"
.venv/bin/python - "$tmp/web/site/index.html" "$tmp/web/manifest.json" "$base/site/" <<'PY'
import hashlib,json,pathlib,sys
source,out,site=pathlib.Path(sys.argv[1]),pathlib.Path(sys.argv[2]),sys.argv[3]
doc={'files':{'index.html':hashlib.sha256(source.read_bytes()).hexdigest()},'generated_at':'2026-10-03T00:00:00Z','site':site,'version':1}
out.write_bytes(json.dumps(doc,sort_keys=True,separators=(',',':')).encode())
PY
manifest_hash="0x$(sha256sum "$tmp/web/manifest.json" | cut -d' ' -f1)"

.venv/bin/python cli/pqrl.py keygen --out "$tmp/e2e.key" >/dev/null
.venv/bin/python - "$tmp/e2e.key" "$owner" "$registry" "$tmp" <<'PY'
from pathlib import Path
import sys
sys.path.insert(0,'cli')
from pqrl import encode_verify_call,keccak256,load_key,project_key,publish_message,register_message
keyfile,owner,registry,tmp=sys.argv[1:]
secret=load_key(keyfile); vk=secret.pubkey.digest(); key=project_key(owner,'paylink')
message=register_message(5042,registry,'0x'+key.hex(),owner,vk)
sig=secret.sign_pure(message,randomize=True,ctx=b'')
call=encode_verify_call(vk,message,sig)
Path(tmp,'vk').write_text('0x'+vk.hex())
Path(tmp,'pop.sig').write_text('0x'+sig.hex())
Path(tmp,'register.slot').write_text('0x'+keccak256(call[4:]).hex())
PY
register_slot="$(cat "$tmp/register.slot")"
cast rpc --rpc-url "$rpc" anvil_setStorageAt "$precompile" "$(cast index bytes32 "$register_slot" 0)" "0x$(printf '%064x' 1)" >/dev/null
vk="$(cat "$tmp/vk")"
pop="$(cat "$tmp/pop.sig")"
.venv/bin/python cli/pqrl.py register-plan --key "$tmp/e2e.key" --owner "$owner" --name paylink \
  --signature-in "$tmp/pop.sig" --registry "$registry" --rpc "$rpc" >"$tmp/register-plan.txt"
grep -Eq '^precompile_check=VALID$' "$tmp/register-plan.txt"
grep -Eq '^register_eth_call=SUCCESS$' "$tmp/register-plan.txt"
cast send --rpc-url "$rpc" --unlocked --from "$owner" "$registry" \
  'registerProject(string,bytes,bytes)' paylink "$vk" "$pop" >/dev/null
key="$(cast call --rpc-url "$rpc" "$registry" 'projectKey(address,string)(bytes32)' "$owner" paylink)"

.venv/bin/python - "$tmp/e2e.key" "$owner" "$registry" "$key" "$manifest_hash" "$base/manifest.json" "$tmp" <<'PY'
from pathlib import Path
import sys
sys.path.insert(0,'cli')
from pqrl import encode_verify_call,keccak256,load_key,parse_hex,publish_message
keyfile,owner,registry,key,manifest_hash,uri,tmp=sys.argv[1:]
secret=load_key(keyfile); vk=secret.pubkey.digest()
message=publish_message(5042,registry,key,1,parse_hex(manifest_hash,32),uri)
sig=secret.sign_pure(message,randomize=True,ctx=b'')
call=encode_verify_call(vk,message,sig)
Path(tmp,'prepared.sig').write_text('0x'+sig.hex())
Path(tmp,'publish.slot').write_text('0x'+keccak256(call[4:]).hex())
Path(tmp,'verify.call').write_text('0x'+call.hex())
PY
publish_slot="$(cat "$tmp/publish.slot")"
cast rpc --rpc-url "$rpc" anvil_setStorageAt "$precompile" "$(cast index bytes32 "$publish_slot" 0)" "0x$(printf '%064x' 1)" >/dev/null
.venv/bin/python cli/pqrl.py publish-plan --key "$tmp/e2e.key" --owner "$owner" --name paylink \
  --seq 1 --manifest "$tmp/web/manifest.json" --uri "$base/manifest.json" \
  --signature-in "$tmp/prepared.sig" --signature-out "$tmp/release.sig" \
  --registry "$registry" --rpc "$rpc" >"$tmp/publish-plan.txt"
grep -Eq '^precompile_check=VALID$' "$tmp/publish-plan.txt"
grep -Eq '^publish_eth_call=SUCCESS$' "$tmp/publish-plan.txt"
signature="$(tr -d '\n' <"$tmp/release.sig")"
cast send --rpc-url "$rpc" --unlocked --from "$owner" "$registry" \
  'publish(bytes32,uint64,bytes32,string,bytes)' "$key" 1 "$manifest_hash" "$base/manifest.json" "$signature" >/dev/null

verify_call="$(cat "$tmp/verify.call")"
mainnet_result="$(cast rpc --rpc-url "$mainnet_rpc" eth_call "{\"to\":\"$precompile\",\"data\":\"$verify_call\"}" latest)"
[[ "$mainnet_result" == *"0000000000000000000000000000000000000000000000000000000000000001"* ]]

.venv/bin/python -m http.server "$web_port" --bind 127.0.0.1 --directory "$tmp/web" >"$tmp/http.log" 2>&1 &
http_pid=$!
for _ in {1..50}; do curl -fsS "$base/manifest.json" >/dev/null 2>&1 && break; sleep .1; done

chrome_lib="$(dirname "$CHROME")/../lib"
common=(--headless --no-sandbox --disable-gpu --disable-dev-shm-usage --virtual-time-budget=9000 --dump-dom)
live_url="$base/verifier/index.html?registry=$registry&rpc=$rpc&owner=$owner&name=paylink&site=$base/site/&debug=1&verify=1&pq=1"
LD_LIBRARY_PATH="$chrome_lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" "$CHROME" "${common[@]}" "$live_url" >"$tmp/live.html"
grep -Eq 'class="status green"' "$tmp/live.html"
grep -Fq 'Matches release #1' "$tmp/live.html"
grep -Fq 'PASS SHA-256 empty' "$tmp/live.html"
grep -Fq 'PASS Keccak-256 135 zero bytes' "$tmp/live.html"
grep -Fq 'PASS Contract message fixed vector' "$tmp/live.html"
grep -Fq 'Post-quantum signature: true' "$tmp/live.html"
grep -Fq "registry=$registry" "$tmp/live.html"

corrupt_url="$live_url&corrupt=1"
LD_LIBRARY_PATH="$chrome_lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" "$CHROME" "${common[@]}" "$corrupt_url" >"$tmp/corrupt.html"
grep -Fq 'Post-quantum signature: false' "$tmp/corrupt.html"

tampered_url="$base/verifier/index.html?registry=$registry&rpc=$rpc&owner=$owner&name=paylink&site=$base/site/&tampered=1"
LD_LIBRARY_PATH="$chrome_lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" "$CHROME" "${common[@]}" "$tampered_url" >"$tmp/tampered.html"
grep -Fq 'Changed or missing files: index.html' "$tmp/tampered.html"
grep -Fq '/verifier/demo-tampered/' "$tmp/tampered.html"
echo "e2e: GREEN real copy; table-checked PQ true; corrupted signature false; real precompile replay true; RED inert tampered copy"
