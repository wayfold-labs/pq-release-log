# PQ Release Log

PQ Release Log is an admin-free, append-only Arc registry for authenticated static-site releases. An EOA submits transactions, while one offline SLH-DSA-SHA2-128s key is permanently bound to that owner and authenticates every project registration and release. Anyone can check a live site with the wallet-free verifier at <https://wayfold-labs.github.io/pq-release-log/> or with the independent CLI.

Live on Arc mainnet (chain 5042): [registry](https://explorer.arc.io/address/0x75622De31B62e29C04262777B31bddf6a542CE05) ([deployment](https://explorer.arc.io/tx/0x24558b1c1029f15fba80e957e1005cace167f4efe3882c941ffaadb8f7920c08), source verified on [Sourcify](https://repo.sourcify.dev/5042/0x75622De31B62e29C04262777B31bddf6a542CE05), exact match). [Release 1](https://explorer.arc.io/tx/0x1d9f47ed050df6a417752b3b097e058b919d4bfa94b10ca6c9fd31358ae99bf1) seals the live PayLink app (https://wayfold-labs.github.io/arc-miniapp/) in block 24074592.

## What is authenticated

Projects use `keccak256(abi.encode(owner, name))`; names match `[a-z0-9-]{1,64}`. The first `registerProject` by an owner stores `ownerVkHash[owner]`. Every later project for that owner must present the same verification key and a fresh proof of possession. A stolen EOA alone therefore cannot publish to an existing project or create a new name with an attacker-controlled PQ key.

A release signature binds the chain ID, registry address, project key, sequence, manifest SHA-256, and URI Keccak-256. `Published` emits the complete signature, so the verifier works for direct EOA calls, Safes, batched calls, and EIP-7702 execution without decoding top-level transaction calldata.

`verifyFor(key, manifestHash)` deliberately reports whether a hash was ever published and returns its **first** sequence number. That stable historical identity does not mean the release is current. Compare the returned sequence with `latestSeqFor(key)` or the sequence returned by `latest(key)`. There is no revoke or key rotation.

## Threat model and honest limits

| Threat or assumption | Result / mitigation |
|---|---|
| Another owner registers the same name | Harmless: owner-address namespacing produces a different project key. Users still need to pin both owner and name. |
| Owner EOA is stolen but its SLH-DSA key remains safe | The attacker cannot publish or register another project under that owner because all names share the bound PQ-key fingerprint. |
| SLH-DSA key is stolen but the EOA remains safe | The attacker cannot submit a registration or release as the owner. |
| Independent second key vs post-quantum authentication | Today, much of the operational protection comes from requiring two separately stored keys; a second offline ECDSA key could provide similar separation. SLH-DSA additionally provides a long-lived root that does not rely on ECDSA remaining quantum-safe. |
| Hosted bytes change after release | A check detects changed or missing **manifest-listed** files. Unlisted files, selective responses, service workers, and dependencies fetched by those files are outside the commitment. |
| GitHub account/origin serving PayLink, manifests, and verifier is compromised | The hosted verifier can lie. Use `pqrl.py verify-site`, or a saved `docs/index.html`, and compare its published SHA-256 below. |
| Arc RPC lies or is unavailable | Both browser and CLI trust the configured RPC for chain state. Repeat against an independent Arc mainnet RPC when the result matters. Production browser RPC/registry/chain ID are fixed; URL overrides are accepted only on localhost. |
| User does not check, or the server targets other visitors | No protection. PQ Release Log detects evidence observed during a check; it does not prevent deployment or delivery of bad bytes. |

The verifier and PayLink currently share a GitHub account and origin. That is why the CLI and published verifier digest are security controls, not merely developer conveniences.

## Manifest format

The manifest is canonical UTF-8 JSON: sorted keys, compact separators, `/` paths, lowercase SHA-256 file hashes, and a non-empty `files` object. The on-chain `manifestHash` is SHA-256 of the exact manifest bytes. Local directory mode requires an explicit HTTPS `--site`, refuses `file:`, skips hidden paths such as `.git/` and `.nojekyll`, and prints every included file for review.

```json
{"files":{"index.html":"2d711642b726b044..."},"generated_at":"2026-10-03T12:00:00Z","site":"https://example.test/","version":1}
```

```sh
.venv/bin/python cli/pqrl.py manifest public \
  --site https://example.test/ --out manifest.json

.venv/bin/python cli/pqrl.py manifest \
  --base-url https://example.test/ \
  --files index.html,assets/app.js --out manifest.json
```

Serve the site and the manifest with `Access-Control-Allow-Origin` permitting the verifier origin (or `*`). Third parties host their manifest at their own HTTPS URL; they cannot publish into this repository’s Pages deployment.

## Register and publish

Supported Python versions are 3.10 through 3.14. `requirements.txt` contains hashes for every file published for `slh-dsa==0.2.5`, including platform wheels, the universal wheel, and sdist. Key creation is exclusive at mode `0600`; the CLI rejects other permissions and never prints secret key material.

```sh
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r cli/requirements.txt
.venv/bin/python cli/pqrl.py keygen --out keys/my-project.key
```

Registration is step 0 and happens once before the first release. `register-plan` signs the proof of possession, requires registry bytecode and chain 5042, checks the real precompile, simulates `registerProject` from `--owner`, and prints a shell-quoted `cast send` command only after every gate passes.

```sh
.venv/bin/python cli/pqrl.py register-plan \
  --key keys/my-project.key \
  --owner 0xYourChecksummedOrLowercaseOwner \
  --name my-project
```

Build and host the canonical manifest, then use `publish-plan`. It checks registry code and chain ID; checks the on-chain owner, verification key, and `latestSeq + 1`; verifies the signature through the precompile; simulates `publish`; writes the signature; and only then prints the complete command. Replace the printed `<KEYSTORE>` account placeholder with the intended Foundry account.

```sh
.venv/bin/python cli/pqrl.py publish-plan \
  --key keys/my-project.key \
  --owner 0xYourChecksummedOrLowercaseOwner \
  --name my-project --seq 1 \
  --manifest manifests/my-project-1.json \
  --uri https://your-origin.example/manifests/my-project-1.json
```

Neither plan broadcasts. A placeholder registry, code-less address, wrong chain, wrong owner/key/sequence, failed precompile check, or reverted simulation exits non-zero before a send command is printed.

## Independent site verification

The CLI provides the mitigation for a compromised hosted verifier. It reads `project`/`release` from Arc, fetches and authenticates the manifest, hashes every listed file, and prints the effective registry, RPC, owner, name, site, release, verification-key fingerprint, and file count.

```sh
.venv/bin/python cli/pqrl.py verify-site \
  --owner 0x3DF09eF258C7589508aD92b48896cE9763Df7231 \
  --name paylink \
  --site https://wayfold-labs.github.io/arc-miniapp/
```

The SHA-256 of the reviewed self-contained verifier is:

```text
1bb5f995e1486d5d5604ef87e7fe4ac5bdab5a8f5b6874126bf4799d69f09930  docs/index.html
```

A saved copy works from `file://` after the real registry is inserted. Compare the saved bytes with this digest before trusting its verdict.

## Browser verifier and URL parameters

The page uses no wallet, external script, font, or HTML injection. Its CSP defaults to no resources, authorizes only its hashed inline script, explicitly limits connections, and forbids frame/object loads. It validates transaction hashes, owner addresses (lowercase or EIP-55), and project names before using RPC data. The verdict always shows the effective registry, RPC, owner, name, checked site, manifest site, file count, verification-key fingerprint, and registration block. Non-default owner/name and mismatched `manifest.site` values receive prominent warnings.

Production accepts these parameters: `owner`, `name`, `site`, `lang=es`, `debug=1`, `verify=1`, `pq=1`, and `tampered=1`. Automatic verification is disabled if owner or name differs from the defaults. `registry` and `rpc` are ignored except on `localhost`/`127.0.0.1`. The local-only `corrupt=1` parameter flips one emitted-signature byte for e2e testing. The inert tampered demo is marked “do not use,” blocks interaction, and carries `noindex` metadata.

`?debug=1` runs SHA-256, Keccak rate-boundary (135/136/271 bytes), ABI/project-key, contract-message, selector, and event-topic vectors. Changing EN/ES re-renders the current verdict, PQ result, release history, dates, title, and errors rather than resetting state.

## Build and test

Prerequisites: Foundry (`forge`, `cast`, `anvil`), Python 3.10+, `curl`, and Chrome or Chrome Headless Shell for e2e. `forge-std` is vendored under `lib/`; no install step or `rg` is needed.

```sh
forge build
forge test
.venv/bin/python test/test_cli.py
./test/killtest.sh
CHROME=/path/to/chrome-headless-shell ./test/e2e.sh
```

The mainnet kill test is read-only and uses state overrides. It asserts exact custom-error selectors and reports separate register-only and publish-only EOA estimates; harness measurements are explicitly labeled inner execution. The final run measured 516,960 gas to register and 628,375 gas to publish, below the 1,000,000 publish gate (randomized signature bytes can shift calldata gas slightly). The e2e test uses a table-checking precompile mock, proves a corrupted signature is false, and replays the exact accepted verifier calldata against the real Arc mainnet precompile.

## License

MIT — see [LICENSE](LICENSE).
