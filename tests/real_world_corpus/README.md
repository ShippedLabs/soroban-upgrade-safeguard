# Real-World Contract Upgrade Validation Corpus

This directory contains a reproducible validation corpus of real-world Soroban smart contract upgrade pairs drawn from deployed Stellar protocols and representative open-source Soroban smart contracts.

## Overview

The corpus exercises `soroban-upgrade-safeguard` against real-world contract shapes, struct layouts, enum evolutions, and interface changes. It verifies that the analyzer correctly categorizes breaking changes vs non-breaking extensions.

### Corpus Upgrade Pairs

| Pair ID | Contract Name | Protocol | Provenance | License | Upgrade Type | Expected Verdict |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `blend_lending_pool` | Blend Protocol Lending Pool | Blend Capital | Mainnet Blend Pool v1 to v2 interface evolution | Apache-2.0 | Additive function, field & enum case | **SAFE** (Minor) |
| `soroswap_router` | Soroswap AMM Router | Soroswap | Soroswap AMM Router parameter removal | MIT | Removed `deadline` parameter | **BREAKING** (Major) |
| `reflector_oracle` | Reflector Price Oracle | Reflector Network | Oracle struct type change (`i128` -> `u128`) | Apache-2.0 | Struct field type modification | **BREAKING** (Major) |
| `stellar_asset_contract` | Stellar Asset Contract | Stellar System | SAC protocol extension for minting & burning | Apache-2.0 | Additive `mint` & `burn` methods | **SAFE** (Minor) |
| `governance_escrow` | Governance Voting Escrow | Soroban Governance | Escrow voting method signature modification | MIT | Added `weight` parameter | **BREAKING** (Major) |

## Provenance and Licensing

All binaries in the corpus originate from open-source Soroban contract implementations:
- **Blend Protocol**: Licensed under [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0).
- **Soroswap DEX**: Licensed under [MIT](https://opensource.org/licenses/MIT).
- **Reflector Oracle**: Licensed under [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0).
- **Stellar Asset Contract**: Licensed under [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0).
- **Governance Protocol**: Licensed under [MIT](https://opensource.org/licenses/MIT).

Full metadata and expected verdicts are specified in [`manifest.json`](manifest.json).

## Running the Corpus

### Default CI Execution (Hermetic & Fast)
By default, the real-world validation corpus is **ignored** during standard `cargo test` invocations to keep CI fast, hermetic, and offline:

```bash
cargo test --test real_world_corpus
# Output: test test_real_world_corpus_validation ... ignored
```

### Opt-In Execution
To run the validation corpus, pass `--ignored` to the test harness:

```bash
cargo test --test real_world_corpus -- --ignored --nocapture
```

or set the environment variable:

```bash
REAL_WORLD_CORPUS=1 cargo test --test real_world_corpus -- --ignored
```

## Refreshing & Rebuilding the Corpus

To re-compile the WASM binaries reproducibly from contract source files:

```bash
bash tests/real_world_corpus/refresh_corpus.sh
```

or compile directly via:

```bash
bash tests/real_world_corpus/build_corpus_fixtures.sh
```

To add a new real-world upgrade pair:
1. Add the pair source under `tests/real_world_corpus/fixtures/<pair_v1>` and `<pair_v2>`.
2. Update `build_corpus_fixtures.sh` to compile the new WASMs into `tests/real_world_corpus/wasm/`.
3. Add the pair metadata, provenance, licensing, and expected verdict entry to `manifest.json`.
4. Run `cargo test --test real_world_corpus -- --ignored` to verify.
