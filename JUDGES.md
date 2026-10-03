# Judge walkthrough

## 90 seconds, no wallet

1. Open <https://wayfold-labs.github.io/pq-release-log/>. Confirm the effective-check line pins owner `0x3DF09eF258C7589508aD92b48896cE9763Df7231`, project `paylink`, the Arc mainnet RPC/registry, and `https://wayfold-labs.github.io/arc-miniapp/`.
2. Select **Verify live site**. GREEN names the sequence, block, date, checked site, `manifest.site`, file count, verification-key fingerprint, and registration block. An empty manifest cannot pass.
3. Select **Re-verify the post-quantum signature on Arc**. The page reads the signature from the one-block `Published` event—not transaction calldata—and sends the reconstructed message to Arc’s SLH-DSA precompile. This also supports Safe, batch, and EIP-7702 publishes.
4. Select **Try the inert tampered demo**. The checked-site input changes to the demo URL, and RED names `index.html`. The demo visibly says **TAMPERED DEMO — do not use**, blocks interaction, disables wallet payment buttons, and is `noindex`.
5. Switch **ES/EN** after GREEN or RED: the existing verdict, PQ result, history, dates, title, and errors remain intact and are re-rendered. Add `?debug=1` to see the 135/136/271-byte Keccak vectors plus ABI, selector, topic, SHA-256, and shared Solidity message tests.

No connection, signature, transaction, or wallet is requested. Production ignores `rpc` and `registry` URL overrides. It never auto-runs for a non-default owner/name, and warns prominently that a changed owner or name means someone else’s project.

Live on Arc mainnet (chain 5042): [registry](https://explorer.arc.io/address/0x75622De31B62e29C04262777B31bddf6a542CE05) ([deployment](https://explorer.arc.io/tx/0x24558b1c1029f15fba80e957e1005cace167f4efe3882c941ffaadb8f7920c08), source verified on [Sourcify](https://repo.sourcify.dev/5042/0x75622De31B62e29C04262777B31bddf6a542CE05), exact match). [Release 1](https://explorer.arc.io/tx/0x1d9f47ed050df6a417752b3b097e058b919d4bfa94b10ca6c9fd31358ae99bf1) seals the live PayLink app (https://wayfold-labs.github.io/arc-miniapp/) in block 24074592. [Release 1 of the verifier itself](https://explorer.arc.io/tx/0xa48c834305fbb0615b1e76c9a034c383fe04e2d0f23d78d30b12b2a7bbe0355d) (project `pq-release-log`, block 24078644) lets anyone check this page with the CLI: `pqrl.py verify-site --owner 0x3DF09eF258C7589508aD92b48896cE9763Df7231 --name pq-release-log --site https://wayfold-labs.github.io/pq-release-log/`.

## Independent verifier check

The hosted verifier shares the PayLink GitHub account/origin and could lie if that account were compromised. Its reviewed digest is:

```text
1bb5f995e1486d5d5604ef87e7fe4ac5bdab5a8f5b6874126bf4799d69f09930  docs/index.html
```

Use a saved copy after checking that digest, or verify without the hosted page:

```sh
.venv/bin/python cli/pqrl.py verify-site \
  --owner 0x3DF09eF258C7589508aD92b48896cE9763Df7231 \
  --name paylink \
  --site https://wayfold-labs.github.io/arc-miniapp/
```

Both methods trust the Arc RPC response. Only manifest-listed files are covered. The system detects observed changes; it does not prevent bad deployment or selective delivery.

## Publish your own release

Prerequisites are Foundry, Python 3.10+ (supported through 3.14), and a host that serves both files and the manifest over HTTPS with CORS. `forge-std` is already vendored in `lib/`. The dependency file includes every published `slh-dsa==0.2.5` artifact hash.

```sh
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r cli/requirements.txt
.venv/bin/python cli/pqrl.py keygen --out keys/my-project.key
```

### Step 0: register

The first registration binds one PQ-key fingerprint to the owner. All later names for the same owner require that same key plus a new proof of possession. `register-plan` checks registry code, chain ID, the real precompile, and a simulation from the owner before printing a send command.

```sh
.venv/bin/python cli/pqrl.py register-plan \
  --key keys/my-project.key \
  --owner 0xYourChecksummedOrLowercaseOwner \
  --name my-project
```

Replace `<KEYSTORE>` in the final printed command and execute it. There is no key rotation, so back up the offline key before registration.

### Step 1: manifest and hosting

The directory form requires an explicit HTTPS site, excludes hidden paths, and prints the exact inventory:

```sh
.venv/bin/python cli/pqrl.py manifest public \
  --site https://your-origin.example/ \
  --out manifests/my-project-1.json
```

Host the unchanged manifest at an HTTPS URL you control. Do not use the project’s `wayfold-labs.github.io` manifest path: third parties cannot write there. Both the manifest host and checked site must permit cross-origin GETs from the verifier.

### Step 2: publish

```sh
.venv/bin/python cli/pqrl.py publish-plan \
  --key keys/my-project.key \
  --owner 0xYourChecksummedOrLowercaseOwner \
  --name my-project --seq 1 \
  --manifest manifests/my-project-1.json \
  --uri https://your-origin.example/manifests/my-project-1.json
```

The plan checks bytecode and chain ID, on-chain owner/key/next sequence, the precompile, and `eth_call`. It writes the signature and prints the complete shell-quoted `cast send` command only after all checks pass. Review it, replace `<KEYSTORE>`, and execute it.

## Reproducibility gates

```sh
forge build
forge test
.venv/bin/python test/test_cli.py
./test/killtest.sh
CHROME=/path/to/chrome-headless-shell ./test/e2e.sh
```

Expected current totals/results:

- Foundry: 19 passed, including per-owner key binding, event signature, stable first-sequence semantics, code-less/64-byte precompile replies, and Keccak boundary vectors.
- Python: 2 passed (boundary vectors and safe manifest construction).
- Mainnet kill test: PASS with exact `InvalidReleaseSignature` (`0xcda44837`) and `InvalidProofOfPossession` (`0x92536faf`) data; final register-only estimate 516,960 gas; final publish-only estimate 628,375 gas; publish remains below 1,000,000. Randomized signature bytes can shift calldata gas slightly.
- E2E: GREEN real copy, table-checked PQ true, corrupted signature false, real-mainnet precompile replay true, and RED inert tampered copy.
