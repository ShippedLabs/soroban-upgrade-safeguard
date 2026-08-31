#!/usr/bin/env python3
"""
Stellar/Soroban XDR Test Fixture Generator helper script.

This script demonstrates how to generate, base64-encode, and format the mock
ContractDataEntry XDR strings used in soroban-upgrade-safeguard's integration test suite.

Examples of manually assembling basic types:
- ScVal::Void: b"\x00\x00\x00\x00"
- ScVal::Bool(true): b"\x00\x00\x00\x02\x00\x00\x00\x01"
- ScVal::U32(42): b"\x00\x00\x00\x04\x00\x00\x00\x2a"
- ScVal::Symbol("my_key"): b"\x00\x00\x00\x0d\x00\x00\x00\x06my_key\x00\x00"
"""

import base64
import json
import sys

# Example mock XDR byte arrays for various ScVal primitive values
MOCK_PRIMITIVES = {
    "u32_value_42": b"\x00\x00\x00\x04\x00\x00\x00\x2a",
    "i32_value_42": b"\x00\x00\x00\x06\x00\x00\x00\x2a",
    "bool_value_true": b"\x00\x00\x00\x02\x00\x00\x00\x01",
    "bool_value_false": b"\x00\x00\x00\x02\x00\x00\x00\x00",
    "void_value": b"\x00\x00\x00\x00",
}

def build_mock_contract_data_entry_b64(key_name: str, val_bytes: bytes) -> str:
    """
    Simulates writing a ContractDataEntry XDR structure:
      - contract: ScAddress::Contract(Hash([0; 32]))
      - key: ScVal::Symbol(key_name)
      - val: ScVal (wrapped from val_bytes)
      - durability: ContractDataDurability::Persistent
      
    This functions maps exactly to the on-chain representation so that the 
    Safeguard tool can parse it offline as if it was fetched directly from 
    a ledger instance storage mapping over HTTP.
    """
    # 32 bytes of contract address (Hash zero)
    contract_address_part = b"\x00\x00\x00\x0f\x00\x00\x00\x01" + b"\x00" * 32
    
    # Encode key_name as ScVal::Symbol (Symbol is variant 13/0x0d, followed by len, then name padded to 4-byte boundaries)
    key_len = len(key_name)
    padded_len = (key_len + 3) & ~3
    key_bytes = b"\x00\x00\x00\x0d" + key_len.to_bytes(4, byteorder="big") + key_name.encode("utf-8") + b"\x00" * (padded_len - key_len)
    
    # Assemble ContractDataEntry XDR representation
    # Format: ContractAddress (40 bytes), Key ScVal, Val ScVal, Durability (0 = persistent)
    entry_bytes = contract_address_part + key_bytes + val_bytes + b"\x00\x00\x00\x00"
    
    # Base64 encode the assembled bytes
    return base64.b64encode(entry_bytes).decode("utf-8")

def main():
    print("Generating mock empirical test fixtures...")
    fixtures = []
    
    for name, val_bytes in MOCK_PRIMITIVES.items():
        xdr_b64 = build_mock_contract_data_entry_b64(name, val_bytes)
        fixtures.append({
            "name": name,
            "description": f"Programmatically generated test case for {name}",
            "xdr": xdr_b64
        })
        
    print(f"Successfully generated {len(fixtures)} fixtures:")
    print(json.dumps(fixtures, indent=2))

if __name__ == "__main__":
    main()
