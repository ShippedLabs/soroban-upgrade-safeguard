#!/bin/bash
set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
FIXTURES_DIR="${SCRIPT_DIR}/fixtures"
WASM_DIR="${SCRIPT_DIR}/wasm"
TARGET_DIR="${SCRIPT_DIR}/target"

mkdir -p "${WASM_DIR}"
mkdir -p "${TARGET_DIR}"

echo "Building real-world validation corpus WASM binaries..."

pairs=(
  "blend_pool_v1:blend_pool_v1.wasm"
  "blend_pool_v2:blend_pool_v2.wasm"
  "soroswap_router_v1:soroswap_router_v1.wasm"
  "soroswap_router_v2:soroswap_router_v2.wasm"
  "reflector_oracle_v1:reflector_oracle_v1.wasm"
  "reflector_oracle_v2:reflector_oracle_v2.wasm"
  "sac_token_v1:sac_token_v1.wasm"
  "sac_token_v2:sac_token_v2.wasm"
  "gov_escrow_v1:gov_escrow_v1.wasm"
  "gov_escrow_v2:gov_escrow_v2.wasm"
)

for entry in "${pairs[@]}"; do
  IFS=":" read -r dir_name out_wasm <<< "${entry}"
  echo "Compiling ${dir_name}..."
  cargo build --manifest-path "${FIXTURES_DIR}/${dir_name}/Cargo.toml" --target wasm32-unknown-unknown --target-dir "${TARGET_DIR}" --release
  
  pkg_name=$(grep '^name =' "${FIXTURES_DIR}/${dir_name}/Cargo.toml" | cut -d '"' -f 2 | tr '-' '_')
  built_wasm="${TARGET_DIR}/wasm32-unknown-unknown/release/${pkg_name}.wasm"
  
  if [ -f "${built_wasm}" ]; then
    cp "${built_wasm}" "${WASM_DIR}/${out_wasm}"
    echo "  -> Saved ${out_wasm}"
  else
    echo "Error: WASM not found at ${built_wasm}"
    exit 1
  fi
done

echo "Successfully built all real-world corpus binaries into ${WASM_DIR}!"
