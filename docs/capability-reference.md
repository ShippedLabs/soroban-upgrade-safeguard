# Soroban Host Import Capability Reference

Registry version `1`. Generated from `soroban-env-common/env.json` in [stellar/rs-soroban-env](https://github.com/stellar/rs-soroban-env). See [Updating the Capability Registry](capability-registry.md) for the regeneration process.

197 recognized host imports across 10 capability groups. Baseline protocol: `20`.

## Context

| Wire Import | Capability ID | Min Protocol | Description |
| --- | --- | --- | --- |
| `x::1` | `context.contract_event` | 20 | Records a contract event. `topics` is expected to be a `SCVec`. Event size is limited by network configuration. |
| `x::5` | `context.fail_with_error` | 20 | Causes the currently executing contract to fail immediately with a provided error code, which must be of error-type `ScErrorType::Contract`. Does not actually return. |
| `x::7` | `context.get_current_contract_address` | 20 | Get the Address object for the current contract. |
| `x::6` | `context.get_ledger_network_id` | 20 | Return the network id (sha256 hash of network passphrase) of the current ledger as `Bytes`. The value is always 32 bytes in length. |
| `x::3` | `context.get_ledger_sequence` | 20 | Return the sequence number of the current ledger as a u32. |
| `x::4` | `context.get_ledger_timestamp` | 20 | Return the timestamp number of the current ledger as a u64. |
| `x::2` | `context.get_ledger_version` | 20 | Return the protocol version of the current ledger as a u32. |
| `x::8` | `context.get_max_live_until_ledger` | 20 | Returns the max ledger sequence that an entry can live to (inclusive). |
| `x::_` | `context.log_from_linear_memory` | 20 | Emit a diagnostic event containing a message and sequence of `Val`s. |
| `x::0` | `context.obj_cmp` | 20 | Compare two objects, or at least one object to a non-object, structurally. Returns -1 if a<b, 1 if a>b, or 0 if a==b. |

## Integer

| Wire Import | Capability ID | Min Protocol | Description |
| --- | --- | --- | --- |
| `i::F` | `int.duration_obj_from_u64` | 20 | Convert a `u64` to a `Duration` object. |
| `i::G` | `int.duration_obj_to_u64` | 20 | Convert a `Duration` object a `u64`. |
| `i::v` | `int.i256_add` | 20 | Performs checked integer addition. Computes `lhs + rhs`, returning `ScError` if overflow occurred. |
| `i::y` | `int.i256_div` | 20 | Performs checked integer division. Computes `lhs / rhs`, returning `ScError` if `rhs == 0` or overflow occurred. |
| `i::x` | `int.i256_mul` | 20 | Performs checked integer multiplication. Computes `lhs * rhs`, returning `ScError` if overflow occurred. |
| `i::A` | `int.i256_pow` | 20 | Performs checked exponentiation. Computes `lhs.exp(rhs)`, returning `ScError` if overflow occurred. |
| `i::z` | `int.i256_rem_euclid` | 20 | Performs checked Euclidean modulo. Computes `lhs % rhs`, returning `ScError` if `rhs == 0` or overflow occurred. |
| `i::B` | `int.i256_shl` | 20 | Performs checked shift left. Computes `lhs << rhs`, returning `ScError` if `rhs` is larger than or equal to the number of bits in `lhs`. |
| `i::C` | `int.i256_shr` | 20 | Performs checked shift right. Computes `lhs >> rhs`, returning `ScError` if `rhs` is larger than or equal to the number of bits in `lhs`. |
| `i::w` | `int.i256_sub` | 20 | Performs checked integer subtraction. Computes `lhs - rhs`, returning `ScError` if overflow occurred. |
| `i::h` | `int.i256_val_from_be_bytes` | 20 | Create a I256 `Val` from its representation as a byte array in big endian. |
| `i::i` | `int.i256_val_to_be_bytes` | 20 | Return the memory representation of this I256 `Val` as a byte array in big endian byte order. |
| `i::6` | `int.obj_from_i128_pieces` | 20 | Convert the high and low 64-bit words of an i128 to an object containing an i128. |
| `i::g` | `int.obj_from_i256_pieces` | 20 | Convert the four 64-bit words of an i256 (big-endian) to an object containing an i256. |
| `i::1` | `int.obj_from_i64` | 20 | Convert an `i64` to an object containing an `i64`. |
| `i::3` | `int.obj_from_u128_pieces` | 20 | Convert the high and low 64-bit words of a u128 to an object containing a u128. |
| `i::9` | `int.obj_from_u256_pieces` | 20 | Convert the four 64-bit words of a u256 (big-endian) to an object containing a u256. |
| `i::_` | `int.obj_from_u64` | 20 | Convert a `u64` to an object containing a `u64`. |
| `i::8` | `int.obj_to_i128_hi64` | 20 | Extract the high 64 bits from an object containing an i128. |
| `i::7` | `int.obj_to_i128_lo64` | 20 | Extract the low 64 bits from an object containing an i128. |
| `i::j` | `int.obj_to_i256_hi_hi` | 20 | Extract the highest 64-bits (bits 192-255) from an object containing an i256. |
| `i::k` | `int.obj_to_i256_hi_lo` | 20 | Extract bits 128-191 from an object containing an i256. |
| `i::l` | `int.obj_to_i256_lo_hi` | 20 | Extract bits 64-127 from an object containing an i256. |
| `i::m` | `int.obj_to_i256_lo_lo` | 20 | Extract the lowest 64-bits (bits 0-63) from an object containing an i256. |
| `i::2` | `int.obj_to_i64` | 20 | Convert an object containing an `i64` to an `i64`. |
| `i::5` | `int.obj_to_u128_hi64` | 20 | Extract the high 64 bits from an object containing a u128. |
| `i::4` | `int.obj_to_u128_lo64` | 20 | Extract the low 64 bits from an object containing a u128. |
| `i::c` | `int.obj_to_u256_hi_hi` | 20 | Extract the highest 64-bits (bits 192-255) from an object containing a u256. |
| `i::d` | `int.obj_to_u256_hi_lo` | 20 | Extract bits 128-191 from an object containing a u256. |
| `i::e` | `int.obj_to_u256_lo_hi` | 20 | Extract bits 64-127 from an object containing a u256. |
| `i::f` | `int.obj_to_u256_lo_lo` | 20 | Extract the lowest 64-bits (bits 0-63) from an object containing a u256. |
| `i::0` | `int.obj_to_u64` | 20 | Convert an object containing a `u64` to a `u64`. |
| `i::D` | `int.timepoint_obj_from_u64` | 20 | Convert a `u64` to a `Timepoint` object. |
| `i::E` | `int.timepoint_obj_to_u64` | 20 | Convert a `Timepoint` object to a `u64`. |
| `i::n` | `int.u256_add` | 20 | Performs checked integer addition. Computes `lhs + rhs`, returning `ScError` if overflow occurred. |
| `i::q` | `int.u256_div` | 20 | Performs checked integer division. Computes `lhs / rhs`, returning `ScError` if `rhs == 0` or overflow occurred. |
| `i::p` | `int.u256_mul` | 20 | Performs checked integer multiplication. Computes `lhs * rhs`, returning `ScError` if overflow occurred. |
| `i::s` | `int.u256_pow` | 20 | Performs checked exponentiation. Computes `lhs.exp(rhs)`, returning `ScError` if overflow occurred. |
| `i::r` | `int.u256_rem_euclid` | 20 | Performs checked Euclidean modulo. Computes `lhs % rhs`, returning `ScError` if `rhs == 0` or overflow occurred. |
| `i::t` | `int.u256_shl` | 20 | Performs checked shift left. Computes `lhs << rhs`, returning `ScError` if `rhs` is larger than or equal to the number of bits in `lhs`. |
| `i::u` | `int.u256_shr` | 20 | Performs checked shift right. Computes `lhs >> rhs`, returning `ScError` if `rhs` is larger than or equal to the number of bits in `lhs`. |
| `i::o` | `int.u256_sub` | 20 | Performs checked integer subtraction. Computes `lhs - rhs`, returning `ScError` if overflow occurred. |
| `i::a` | `int.u256_val_from_be_bytes` | 20 | Create a U256 `Val` from its representation as a byte array in big endian. |
| `i::b` | `int.u256_val_to_be_bytes` | 20 | Return the memory representation of this U256 `Val` as a byte array in big endian byte order. |
| `i::L` | `int.i256_checked_add` | 26 | Performs checked addition. Computes `lhs + rhs`, returning `Void` if overflow occurred, otherwise returns `I256Val`. |
| `i::N` | `int.i256_checked_mul` | 26 | Performs checked multiplication. Computes `lhs * rhs`, returning `Void` if overflow occurred, otherwise returns `I256Val`. |
| `i::O` | `int.i256_checked_pow` | 26 | Performs checked exponentiation. Computes `lhs.exp(rhs)`, returning `Void` if overflow occurred, otherwise returns `I256Val`. |
| `i::M` | `int.i256_checked_sub` | 26 | Performs checked subtraction. Computes `lhs - rhs`, returning `Void` if overflow occurred, otherwise returns `I256Val`. |
| `i::H` | `int.u256_checked_add` | 26 | Performs checked addition. Computes `lhs + rhs`, returning `Void` if overflow occurred, otherwise returns `U256Val`. |
| `i::J` | `int.u256_checked_mul` | 26 | Performs checked multiplication. Computes `lhs * rhs`, returning `Void` if overflow occurred, otherwise returns `U256Val`. |
| `i::K` | `int.u256_checked_pow` | 26 | Performs checked exponentiation. Computes `lhs.exp(rhs)`, returning `Void` if overflow occurred, otherwise returns `U256Val`. |
| `i::I` | `int.u256_checked_sub` | 26 | Performs checked subtraction. Computes `lhs - rhs`, returning `Void` if overflow occurred, otherwise returns `U256Val`. |

## Map

| Wire Import | Capability ID | Min Protocol | Description |
| --- | --- | --- | --- |
| `m::2` | `map.map_del` | 20 | Remove a key/value mapping from a map if it exists, traps if doesn't. |
| `m::1` | `map.map_get` | 20 | Get the value for a key from a map. Traps if key is not found. |
| `m::4` | `map.map_has` | 20 | Test for the presence of a key in a map. Returns Bool. |
| `m::5` | `map.map_key_by_pos` | 20 | Get the key from a map at position `i`. If `i` is an invalid position, return ScError. |
| `m::7` | `map.map_keys` | 20 | Return a new vector containing all the keys in a map. The new vector is ordered in the original map's key-sorted order. |
| `m::3` | `map.map_len` | 20 | Get the size of a map. |
| `m::_` | `map.map_new` | 20 | Create an empty new map. |
| `m::9` | `map.map_new_from_linear_memory` | 20 | Return a new map initialized from a pair of equal `len` length arrays, one for keys and one for values, specified by linear memory addresses. Key strings are specified as `len` 8 byte slices consisting of the 4 byte pointer and 4 byte length. Actual keys must be byte strings sorted in ascending order and be convertible to `Symbol` type. Values may be arbitrary `Val`s. Panics if any of the invariants above are violated. |
| `m::0` | `map.map_put` | 20 | Insert a key/value mapping into an existing map, and return the map object handle. If the map already has a mapping for the given key, the previous value is overwritten. |
| `m::a` | `map.map_unpack_to_linear_memory` | 20 | Copy all value `Val`s from `map` to the linear memory array at `vals_pos` address. `len` must match the number of entries in `map`. Map keys must be of `Symbol` type and must match the key byte strings in the linear memory array at `keys_pos` address. Key strings are specified as 8 byte slices consisting of the 4 byte pointer and 4 byte length. Keys must be sorted in ascending order. Panics if any of the invariants above are violated. |
| `m::6` | `map.map_val_by_pos` | 20 | Get the value from a map at position `i`. If `i` is an invalid position, return ScError. |
| `m::8` | `map.map_values` | 20 | Return a new vector containing all the values in a map. The new vector is ordered in the original map's key-sorted order. |
| `m::b` | `map.sparse_map_new_from_linear_memory` | 28 | Return a new map initialized from a pair of equal `len` length arrays, one for keys and one for values, specified by linear memory addresses. Key strings are specified as `len` 8 byte slices consisting of the 4 byte pointer and 4 byte length. Actual keys must be byte strings sorted in ascending order and be convertible to `Symbol` type. Values may be arbitrary `Val`s. Key-value pairs where the value is `Void` are not included into the final map. Panics if any of the invariants above are violated. |
| `m::c` | `map.sparse_map_unpack_to_linear_memory` | 28 | Fetch value `Val`s from `map` to the linear memory array at `vals_pos` address according to the key byte strings stored in linear memory at `keys_pos`. Key strings are specified as 8 byte slices consisting of the 4 byte pointer and 4 byte length. Keys must be sorted in ascending order. The map keys are expected to have `Symbol` type and its content bytes are matched to the input keys. If there is no matching map key, the corresponding value is set to `Void`. Panics if any of the invariants above are violated. |

## Vec

| Wire Import | Capability ID | Min Protocol | Description |
| --- | --- | --- | --- |
| `v::b` | `vec.vec_append` | 20 | Clone the vector `v1`, then moves all the elements of vector `v2` into it. Return the new vector. Traps if number of elements in the vector overflows a u32. |
| `v::9` | `vec.vec_back` | 20 | Return the last element in the vector. Traps if the vector is empty |
| `v::f` | `vec.vec_binary_search` | 20 | Binary search a sorted vector for a given element. If it exists, the high 32 bits of the return value is 0x0000_0001 and the low 32 bits contain the u32 index of the element. If it does not exist, the high 32 bits of the return value is 0x0000_0000 and the low-32 bits contain the u32 index at which the element would need to be inserted into the vector to maintain sorted order. |
| `v::2` | `vec.vec_del` | 20 | Delete an element in a vector at index `i`, shifting all elements after it to the left. Return the new vector. Traps if the index is out of bound. |
| `v::d` | `vec.vec_first_index_of` | 20 | Get the index of the first occurrence of a given element in the vector. Returns the u32 index of the value if it's there. Otherwise, it returns `Void`. |
| `v::8` | `vec.vec_front` | 20 | Return the first element in the vector. Traps if the vector is empty |
| `v::1` | `vec.vec_get` | 20 | Returns the element at index `i` of the vector. Traps if the index is out of bound. |
| `v::a` | `vec.vec_insert` | 20 | Inserts an element at index `i` within the vector, shifting all elements after it to the right. Traps if the index is out of bound |
| `v::e` | `vec.vec_last_index_of` | 20 | Get the index of the last occurrence of a given element in the vector. Returns the u32 index of the value if it's there. Otherwise, it returns `Void`. |
| `v::3` | `vec.vec_len` | 20 | Returns length of the vector. |
| `v::_` | `vec.vec_new` | 20 | Creates an empty new vector. |
| `v::g` | `vec.vec_new_from_linear_memory` | 20 | Return a new vec initialized from an input slice of Vals given by a linear-memory address and length in Vals. |
| `v::7` | `vec.vec_pop_back` | 20 | Removes the last element from the vector and returns the new vector. Traps if original vector is empty. |
| `v::5` | `vec.vec_pop_front` | 20 | Removes the first element from the vector and returns the new vector. Traps if original vector is empty. |
| `v::6` | `vec.vec_push_back` | 20 | Appends an element to the back of the vector. |
| `v::4` | `vec.vec_push_front` | 20 | Push a value to the front of a vector. |
| `v::0` | `vec.vec_put` | 20 | Update the value at index `i` in the vector. Return the new vector. Trap if the index is out of bounds. |
| `v::c` | `vec.vec_slice` | 20 | Copy the elements from `start` index until `end` index, exclusive, in the vector and create a new vector from it. Return the new vector. Traps if the index is out of bound. |
| `v::h` | `vec.vec_unpack_to_linear_memory` | 20 | Copy the Vals of a vec into an array at a given linear-memory address and length in Vals. |

## Ledger/Storage

| Wire Import | Capability ID | Min Protocol | Description |
| --- | --- | --- | --- |
| `l::4` | `ledger.create_asset_contract` | 20 | Creates the instance of Stellar Asset contract corresponding to the provided asset. `serialized_asset` is `stellar::Asset` XDR serialized to bytes format. Returns the address of the created contract. |
| `l::3` | `ledger.create_contract` | 20 | Creates the contract instance on behalf of `deployer`. `deployer` must authorize this call via Soroban auth framework, i.e. this calls `deployer.require_auth` with respective arguments. `wasm_hash` must be a hash of the contract code that has already been uploaded on this network. `salt` is used to create a unique contract id. Returns the address of the created contract. |
| `l::2` | `ledger.del_contract_data` | 20 |  |
| `l::7` | `ledger.extend_contract_data_ttl` | 20 | If the entry's TTL is below `threshold` ledgers, extend `live_until_ledger_seq` such that TTL == `extend_to`, where TTL is defined as live_until_ledger_seq - current ledger. If attempting to extend the entry past the maximum allowed value (defined as the current ledger + `max_entry_ttl` - 1), and the entry is `Persistent`, its new `live_until_ledger_seq` will be clamped to the max; if the entry is `Temporary`, the function traps. |
| `l::9` | `ledger.extend_contract_instance_and_code_ttl` | 20 | If the TTL for the provided contract instance and code (if applicable) is below `threshold` ledgers, extend `live_until_ledger_seq` such that TTL == `extend_to`, where TTL is defined as live_until_ledger_seq - current ledger. If attempting to extend past the maximum allowed value (defined as the current ledger + `max_entry_ttl` - 1), the new `live_until_ledger_seq` will be clamped to the max. |
| `l::8` | `ledger.extend_current_contract_instance_and_code_ttl` | 20 | If the TTL for the current contract instance and code (if applicable) is below `threshold` ledgers, extend `live_until_ledger_seq` such that TTL == `extend_to`, where TTL is defined as live_until_ledger_seq - current ledger. If attempting to extend past the maximum allowed value (defined as the current ledger + `max_entry_ttl` - 1), the new `live_until_ledger_seq` will be clamped to the max. |
| `l::b` | `ledger.get_asset_contract_id` | 20 | Get the id of the Stellar Asset contract corresponding to the provided asset without creating the instance. `serialized_asset` is `stellar::Asset` XDR serialized to bytes format. Returns the address of the would-be asset contract. |
| `l::1` | `ledger.get_contract_data` | 20 |  |
| `l::a` | `ledger.get_contract_id` | 20 | Get the id of a contract without creating it. `deployer` is address of the contract deployer. `salt` is used to create a unique contract id. Returns the address of the would-be contract. |
| `l::0` | `ledger.has_contract_data` | 20 |  |
| `l::_` | `ledger.put_contract_data` | 20 |  |
| `l::6` | `ledger.update_current_contract_wasm` | 20 | Replaces the executable of the current contract with the provided Wasm code identified by a hash. Wasm entry corresponding to the hash has to already be present in the ledger. The update happens only after the current contract invocation has successfully finished, so this can be safely called in the middle of a function. |
| `l::5` | `ledger.upload_wasm` | 20 | Uploads provided `wasm` bytecode to the network and returns its identifier (SHA-256 hash). No-op in case if the same Wasm object already exists. |
| `l::d` | `ledger.extend_contract_code_ttl` | 21 | If the TTL for the provided contract's code (if applicable) is below `threshold` ledgers, extend `live_until_ledger_seq` such that TTL == `extend_to`, where TTL is defined as live_until_ledger_seq - current ledger. If attempting to extend past the maximum allowed value (defined as the current ledger + `max_entry_ttl` - 1), the new `live_until_ledger_seq` will be clamped to the max. |
| `l::c` | `ledger.extend_contract_instance_ttl` | 21 | If the TTL for the provided contract instance is below `threshold` ledgers, extend `live_until_ledger_seq` such that TTL == `extend_to`, where TTL is defined as live_until_ledger_seq - current ledger. If attempting to extend past the maximum allowed value (defined as the current ledger + `max_entry_ttl` - 1), the new `live_until_ledger_seq` will be clamped to the max. |
| `l::e` | `ledger.create_contract_with_constructor` | 22 | Creates the contract instance on behalf of `deployer`. Created contract must be created from a Wasm that has a constructor. `deployer` must authorize this call via Soroban auth framework, i.e. this calls `deployer.require_auth` with respective arguments. `wasm_hash` must be a hash of the contract code that has already been uploaded on this network. `salt` is used to create a unique contract id. `constructor_args` are forwarded into created contract's constructor (`__constructor`) function. Returns the address of the created contract. |
| `l::f` | `ledger.extend_contract_data_ttl_v2` | 26 | Extend the contract data entry's TTL to be up to `extend_to` ledgers, where TTL is defined as `entry_live_until_ledger_seq - current_ledger_seq`. The TTL extension only actually happens if it is at least `min_extension`, otherwise this function is a no-op. The amount of extension ledgers will not exceed `max_extension` ledgers. If attempting to extend the entry past the maximum allowed value (defined as the current ledger + `max_entry_ttl` - 1), and the entry is `Persistent`, its new `live_until_ledger_seq` will be clamped to the max; if the entry is `Temporary`, the function traps. |
| `l::g` | `ledger.extend_contract_instance_and_code_ttl_v2` | 26 | Extend the contract instance and/or corresponding code entry TTL to be up to `extend_to` ledgers, where TTL is defined as `entry_live_until_ledger_seq - current_ledger_seq`. `extension_scope` defines whether contract instance, code, or both will be extended. The TTL extension only actually happens if it is at least `min_extension`, otherwise this function is a no-op. The amount of extension ledgers will not exceed `max_extension` ledgers. If attempting to extend an entry past the maximum allowed value (defined as the current ledger + `max_entry_ttl` - 1), its new `live_until_ledger_seq` will be clamped to the max. |
| `l::h` | `ledger.create_executable_tag` | 28 | Creates a new `ExecutableTag` object holding the contents of the provided string. The tag acts as a key identifying an executable reference contract data entry. Executable reference entries may be used by other contracts to fetch their executable. |
| `l::i` | `ledger.create_external_ref_contract` | 28 | Creates the contract instance on behalf of `deployer`. `deployer` must authorize this call via Soroban auth framework, i.e. this calls `deployer.require_auth` with respective arguments. Executable is read from the `executable_owner` contract storage entry keyed by `tag`. Currently the only supported external executable kind is hash of an existing Wasm. `salt` is used to create a unique contract id. `constructor_args` are forwarded into created contract's constructor (`__constructor`) function. Returns the address of the created contract. |
| `l::j` | `ledger.update_current_contract_executable_ref` | 28 | Replaces the executable of the current contract with the provided executable reference. Executable is read from the `executable_owner` contract storage entry keyed by `tag`. Currently the only supported external executable kind is hash of an existing Wasm. The update happens only after the current contract invocation has successfully finished, so this can be safely called in the middle of a function. |

## Cross-Contract Call

| Wire Import | Capability ID | Min Protocol | Description |
| --- | --- | --- | --- |
| `d::_` | `call.call` | 20 | Calls a function in another contract with arguments contained in vector `args`. If the call is successful, returns the result of the called function. Traps otherwise. |
| `d::0` | `call.try_call` | 20 | Calls a function in another contract with arguments contained in vector `args`, returning either the result of the called function or an `Error` if the called function failed. The returned error is either a custom `ContractError` that the called contract returns explicitly, or an error with type `Context` and code `InvalidAction` in case of any other error in the called contract (such as a host function failure that caused a trap). `try_call` might trap in a few scenarios where the error can't be meaningfully recovered from, such as running out of budget. |

## Buffer/Bytes

| Wire Import | Capability ID | Min Protocol | Description |
| --- | --- | --- | --- |
| `b::e` | `buf.bytes_append` | 20 | Clone the `Bytes` object `b1`, then moves all the elements of `Bytes` object `b2` into it. Return the new `Bytes`. Traps if its length overflows a u32. |
| `b::c` | `buf.bytes_back` | 20 | Return the last element in the `Bytes` object. Traps if the `Bytes` is empty |
| `b::2` | `buf.bytes_copy_from_linear_memory` | 20 | Copies a segment of the linear memory specified at position `lm_pos` with length `len`, into a `Bytes` object at offset `b_pos`. The `Bytes` object may grow in size to accommodate the new bytes. Traps if the linear memory doesn't have enough bytes. |
| `b::1` | `buf.bytes_copy_to_linear_memory` | 20 | Copies a slice of bytes from a `Bytes` object specified at offset `b_pos` with length `len` into the linear memory at position `lm_pos`. Traps if either the `Bytes` object or the linear memory doesn't have enough bytes. |
| `b::7` | `buf.bytes_del` | 20 | Delete an element in a `Bytes` object at index `i`, shifting all elements after it to the left. Return the new `Bytes`. Traps if the index is out of bound. |
| `b::b` | `buf.bytes_front` | 20 | Return the first element in the `Bytes` object. Traps if the `Bytes` is empty |
| `b::6` | `buf.bytes_get` | 20 | Returns the element at index `i` of the `Bytes` object. Traps if the index is out of bound. |
| `b::d` | `buf.bytes_insert` | 20 | Inserts an element at index `i` within the `Bytes` object, shifting all elements after it to the right. Traps if the index is out of bound |
| `b::8` | `buf.bytes_len` | 20 | Returns length of the `Bytes` object. |
| `b::4` | `buf.bytes_new` | 20 | Create an empty new `Bytes` object. |
| `b::3` | `buf.bytes_new_from_linear_memory` | 20 | Constructs a new `Bytes` object initialized with bytes copied from a linear memory slice specified at position `lm_pos` with length `len`. |
| `b::a` | `buf.bytes_pop` | 20 | Removes the last element from the `Bytes` object and returns the new `Bytes`. Traps if original `Bytes` is empty. |
| `b::9` | `buf.bytes_push` | 20 | Appends an element to the back of the `Bytes` object. |
| `b::5` | `buf.bytes_put` | 20 | Update the value at index `i` in the `Bytes` object. Return the new `Bytes`. Trap if the index is out of bounds. |
| `b::f` | `buf.bytes_slice` | 20 | Copies the elements from `start` index until `end` index, exclusive, in the `Bytes` object and creates a new `Bytes` from it. Returns the new `Bytes`. Traps if the index is out of bound. |
| `b::0` | `buf.deserialize_from_bytes` | 20 | Deserialize a `Bytes` object to get back the (SC)Val. |
| `b::_` | `buf.serialize_to_bytes` | 20 | Serializes an (SC)Val into XDR opaque `Bytes` object. |
| `b::g` | `buf.string_copy_to_linear_memory` | 20 | Copies a slice of bytes from a `String` object specified at offset `s_pos` with length `len` into the linear memory at position `lm_pos`. Traps if either the `String` object or the linear memory doesn't have enough bytes. |
| `b::k` | `buf.string_len` | 20 | Returns length of the `String` object. |
| `b::i` | `buf.string_new_from_linear_memory` | 20 | Constructs a new `String` object initialized with bytes copied from a linear memory slice specified at position `lm_pos` with length `len`. |
| `b::h` | `buf.symbol_copy_to_linear_memory` | 20 | Copies a slice of bytes from a `Symbol` object specified at offset `s_pos` with length `len` into the linear memory at position `lm_pos`. Traps if either the `String` object or the linear memory doesn't have enough bytes. |
| `b::m` | `buf.symbol_index_in_linear_memory` | 20 | Return the index of a Symbol in an array of linear-memory byte-slices, or trap if not found. |
| `b::l` | `buf.symbol_len` | 20 | Returns length of the `Symbol` object. |
| `b::j` | `buf.symbol_new_from_linear_memory` | 20 | Constructs a new `Symbol` object initialized with bytes copied from a linear memory slice specified at position `lm_pos` with length `len`. |
| `b::o` | `buf.bytes_to_string` | 23 | Converts the provided bytes array to string with exactly the same contents. No encoding checks are performed and thus the output string's encoding should be interpreted by the consumer of the string. |
| `b::n` | `buf.string_to_bytes` | 23 | Converts the provided string to bytes with exactly the same contents. |

## Crypto

| Wire Import | Capability ID | Min Protocol | Description |
| --- | --- | --- | --- |
| `c::1` | `crypto.compute_hash_keccak256` | 20 | Returns the keccak256 hash of given input bytes. |
| `c::_` | `crypto.compute_hash_sha256` | 20 |  |
| `c::2` | `crypto.recover_key_ecdsa_secp256k1` | 20 | Recovers the SEC-1-encoded ECDSA secp256k1 public key that produced a given 64-byte `signature` over a given 32-byte `msg_digest` for a given `recovery_id` byte. Warning: The `msg_digest` must be produced by a secure cryptographic hash function on the message, otherwise the attacker can potentially forge signatures. The `signature` is the ECDSA signature `(r, s)` serialized as fixed-size big endian scalar values, both `r`, `s` must be non-zero and `s` must be in the lower range. Returns a `BytesObject` containing 65-bytes representing SEC-1 encoded point in uncompressed format. The `recovery_id` is an integer value `0`, `1`, `2`, or `3`, the low bit (0/1) indicates the parity of the y-coordinate of the `public_key` (even/odd) and the high bit (3/4) indicate if the `r` (x-coordinate of `k x G`) has overflown during its computation. |
| `c::0` | `crypto.verify_sig_ed25519` | 20 |  |
| `c::3` | `crypto.verify_sig_ecdsa_secp256r1` | 21 | Verifies the `signature` using an ECDSA secp256r1 `public_key` on a 32-byte `msg_digest`. Warning: The `msg_digest` must be produced by a secure cryptographic hash function on the message, otherwise the attacker can potentially forge signatures. The `public_key` is expected to be 65 bytes in length, representing a SEC-1 encoded point in uncompressed format. The `signature` is the ECDSA signature `(r, s)` serialized as fixed-size big endian scalar values, both `r`, `s` must be non-zero and `s` must be in the lower range. |
| `c::4` | `crypto.bls12_381_check_g1_is_in_subgroup` | 22 | Checks if the input G1 point is in the correct subgroup. This function will error if `point` is not on the curve |
| `c::a` | `crypto.bls12_381_check_g2_is_in_subgroup` | 22 | Checks if the input G2 point is in the correct subgroup. This function will error if `point` is not on the curve |
| `c::h` | `crypto.bls12_381_fr_add` | 22 | performs addition `(lhs + rhs) mod r` between two BLS12-381 scalar elements (Fr), where r is the subgroup order |
| `c::l` | `crypto.bls12_381_fr_inv` | 22 | performs inversion of a BLS12-381 scalar element (Fr) modulo r (the subgroup order) |
| `c::j` | `crypto.bls12_381_fr_mul` | 22 | performs multiplication `(lhs * rhs) mod r` between two BLS12-381 scalar elements (Fr), where r is the subgroup order |
| `c::k` | `crypto.bls12_381_fr_pow` | 22 | performs exponentiation of a BLS12-381 scalar element (Fr) with a u64 exponent i.e. `lhs.exp(rhs) mod r`, where r is the subgroup order |
| `c::i` | `crypto.bls12_381_fr_sub` | 22 | performs subtraction `(lhs - rhs) mod r` between two BLS12-381 scalar elements (Fr), where r is the subgroup order |
| `c::5` | `crypto.bls12_381_g1_add` | 22 | Adds two BLS12-381 G1 points given in bytes format and returns the resulting G1 point in bytes format. G1 serialization format: `concat(be_bytes(X), be_bytes(Y))` and the most significant three bits of X encodes flags, i.e. bits(X) = [compression_flag, infinity_flag, sort_flag, bit_3, .. bit_383]. This function does NOT perform subgroup check on the inputs. |
| `c::7` | `crypto.bls12_381_g1_msm` | 22 | Performs multi-scalar-multiplication (inner product) on a vector of BLS12-381 G1 points (`Vec<BytesObject>`) by a vector of scalars (`Vec<U256Val>`), and returns the resulting G1 point in bytes format. |
| `c::6` | `crypto.bls12_381_g1_mul` | 22 | Multiplies a BLS12-381 G1 point by a scalar (Fr), and returns the resulting G1 point in bytes format. |
| `c::b` | `crypto.bls12_381_g2_add` | 22 | Adds two BLS12-381 G2 points given in bytes format and returns the resulting G2 point in bytes format. G2 serialization format: concat(be_bytes(X_c1), be_bytes(X_c0), be_bytes(Y_c1), be_bytes(Y_c0)), and the most significant three bits of X_c1 are flags i.e. bits(X_c1) = [compression_flag, infinity_flag, sort_flag, bit_3, .. bit_383]. This function does NOT perform subgroup check on the inputs. |
| `c::d` | `crypto.bls12_381_g2_msm` | 22 | Performs multi-scalar-multiplication (inner product) on a vector of BLS12-381 G2 points (`Vec<BytesObject>`) by a vector of scalars (`Vec<U256Val>`) , and returns the resulting G2 point in bytes format. |
| `c::c` | `crypto.bls12_381_g2_mul` | 22 | Multiplies a BLS12-381 G2 point by a scalar (Fr), and returns the resulting G2 point in bytes format. |
| `c::9` | `crypto.bls12_381_hash_to_g1` | 22 | Hashes a message to a BLS12-381 G1 point, with implementation following the specification in [Hashing to Elliptic Curves](https://datatracker.ietf.org/doc/html/rfc9380) (ciphersuite 'BLS12381G1_XMD:SHA-256_SSWU_RO_'). `dst` is the domain separation tag that will be concatenated with the `msg` during hashing, it is intended to keep hashing inputs of different applications separate. It is required `0 < len(dst_bytes) < 256`. DST **must** be chosen with care to avoid compromising the application's security properties. Refer to section 3.1 in the RFC on requirements of DST. |
| `c::f` | `crypto.bls12_381_hash_to_g2` | 22 | Hashes a message to a BLS12-381 G2 point, with implementation following the specification in [Hashing to Elliptic Curves](https://datatracker.ietf.org/doc/html/rfc9380) (ciphersuite 'BLS12381G2_XMD:SHA-256_SSWU_RO_'). `dst` is the domain separation tag that will be concatenated with the `msg` during hashing, it is intended to keep hashing inputs of different applications separate. It is required `0 < len(dst_bytes) < 256`. DST **must** be chosen with care to avoid compromising the application's security properties. Refer to section 3.1 in the RFC on requirements of DST. |
| `c::e` | `crypto.bls12_381_map_fp2_to_g2` | 22 | Maps a BLS12-381 quadratic extension field element (Fp2) to G2 point. Fp2 serialization format: concat(be_bytes(c1), be_bytes(c0)) |
| `c::8` | `crypto.bls12_381_map_fp_to_g1` | 22 | Maps a BLS12-381 field element (Fp) to G1 point. The input is a BytesObject containing Fp serialized in big-endian order |
| `c::g` | `crypto.bls12_381_multi_pairing_check` | 22 | performs pairing operation on a vector of `G1` (`Vec<BytesObject>`) and a vector of `G2` points (`Vec<BytesObject>`) , return true if the result equals `1_fp12` |
| `c::m` | `crypto.bn254_g1_add` | 25 | Adds two BN254 G1 points. G1 encoding: 64-byte uncompressed format: be_bytes(X)\|\|be_bytes(Y), where X and Y are 32-byte big-endian Fp field elements. The two flag bits (0x80 and 0x40) of the first byte must be unset -- infinity is represented as 64 zero bytes. Points must be on curve with no subgroup check needed (always in subgroup) |
| `c::n` | `crypto.bn254_g1_mul` | 25 | Multiplies a BN254 G1 point by a scalar from the scalar field Fr. The point uses the same 64-byte encoding as bn254_g1_add. The scalar is a U256Val representing a 256-bit integer that is reduced modulo the Fr field order. |
| `c::o` | `crypto.bn254_multi_pairing_check` | 25 | Performs BN254 multi-pairing check over equal-length non-empty vectors of G1 and G2 points. Returns true iff the product of pairings e(G1[0],G2[0])*...*e(G1[n-1],G2[n-1]) equals 1 in Fq12. G1 encoding: 64 bytes as in bn254_g1_add. G2 encoding: 128-byte uncompressed format: be_bytes(X)\|\|be_bytes(Y), where X and Y are Fp2 elements (64 bytes each). Fp2 element encoding: be_bytes(c1)\|\|be_bytes(c0) where c0 is the real part and c1 is the imaginary part (each 32-byte big-endian Fp). The two flag bits (0x80 and 0x40) of the first byte must be unset -- G2 infinity is 128 zero bytes. G2 points must be on curve AND in the correct subgroup. |
| `c::q` | `crypto.poseidon2_permutation` | 25 | Performs Poseidon2 permutation on input vector. input: vector of field elements (length t). field: 'BLS12_381' or 'BN254'. t: state size. d: S-box degree (5 for BLS12_381/BN254). rounds_f: number of full rounds (must be even). rounds_p: number of partial rounds. mat_internal_diag_m_1: internal matrix diagonal minus 1 as Vec<Scalar> (length t). round_constants: (rounds_f+rounds_p)-by-t round constants matrix as Vec<Vec<Scalar>>. Returns output vector after permutation. |
| `c::p` | `crypto.poseidon_permutation` | 25 | Performs Poseidon permutation on input vector. input: vector of field elements (length t). field: 'BLS12_381' or 'BN254'. t: state size. d: S-box degree (5 for BLS12_381/BN254). rounds_f: number of full rounds (must be even). rounds_p: number of partial rounds. mds: t-by-t MDS matrix as Vec<Vec<Scalar>>. round_constants: (rounds_f+rounds_p)-by-t round constants matrix as Vec<Vec<Scalar>>. Returns output vector after permutation. |
| `c::x` | `crypto.bls12_381_g1_is_on_curve` | 26 | Checks if a BLS12-381 G1 point is on the curve (does not check subgroup membership). Returns true if the point is on the curve, false otherwise. |
| `c::y` | `crypto.bls12_381_g2_is_on_curve` | 26 | Checks if a BLS12-381 G2 point is on the curve (does not check subgroup membership). Returns true if the point is on the curve, false otherwise. |
| `c::s` | `crypto.bn254_fr_add` | 26 | Performs addition `(lhs + rhs) mod r` between two BN254 scalar elements (Fr), where r is the subgroup order |
| `c::w` | `crypto.bn254_fr_inv` | 26 | Performs inversion of a BN254 scalar element (Fr) modulo r (the subgroup order) |
| `c::u` | `crypto.bn254_fr_mul` | 26 | Performs multiplication `(lhs * rhs) mod r` between two BN254 scalar elements (Fr), where r is the subgroup order |
| `c::v` | `crypto.bn254_fr_pow` | 26 | Performs exponentiation of a BN254 scalar element (Fr) with a u64 exponent i.e. `lhs.exp(rhs) mod r`, where r is the subgroup order |
| `c::t` | `crypto.bn254_fr_sub` | 26 | Performs subtraction `(lhs - rhs) mod r` between two BN254 scalar elements (Fr), where r is the subgroup order |
| `c::z` | `crypto.bn254_g1_is_on_curve` | 26 | Checks if a BN254 G1 point is on the curve. Returns true if the point is on the curve, false otherwise. |
| `c::r` | `crypto.bn254_g1_msm` | 26 | Performs multi-scalar-multiplication (inner product) on a vector of BN254 G1 points (`Vec<BytesObject>`) by a vector of scalars (`Vec<U256Val>`), and returns the resulting G1 point in 64-byte uncompressed format. |

## Address

| Wire Import | Capability ID | Min Protocol | Description |
| --- | --- | --- | --- |
| `a::2` | `address.address_to_strkey` | 20 | Converts a provided address to Stellar strkey format ('G...' for account or 'C...' for contract). Prefer directly using the Address objects whenever possible. This is only useful in the context of custom messaging protocols (e.g. cross-chain). |
| `a::3` | `address.authorize_as_curr_contract` | 20 | Authorizes sub-contract calls for the next contract call on behalf of the current contract. Every entry in the argument vector corresponds to `InvokerContractAuthEntry` contract type that authorizes a tree of `require_auth` calls on behalf of the current contract. The entries must not contain any authorizations for the direct contract call, i.e. if current contract needs to call contract function F1 that calls function F2 both of which require auth, only F2 should be present in `auth_entries`. |
| `a::0` | `address.require_auth` | 20 | Checks if the address has authorized the invocation of the current contract function with all the arguments of the invocation. Traps if the invocation hasn't been authorized. |
| `a::_` | `address.require_auth_for_args` | 20 | Checks if the address has authorized the invocation of the current contract function with the provided arguments. Traps if the invocation hasn't been authorized. |
| `a::1` | `address.strkey_to_address` | 20 | Converts a provided Stellar strkey address of an account or a contract ('G...' or 'C...' respectively) to an address object. `strkey` can be either `BytesObject` or `StringObject` (the contents should represent the `G.../C...` string in both cases). Any other valid or invalid strkey (e.g. 'S...') will trigger an error. Prefer directly using the Address objects whenever possible. This is only useful in the context of custom messaging protocols (e.g. cross-chain). |
| `a::6` | `address.get_address_executable` | 23 | Returns the executable corresponding to the provided address. When the address does not exist on-chain, returns `Void` value. When it does exist, returns a value of `AddressExecutable` contract type. It is an enum with `Wasm` value and the corresponding Wasm hash for the Wasm contracts, `StellarAsset` value for Stellar Asset contract instances, and `Account` value for the 'classic' (G-) accounts. |
| `a::4` | `address.get_address_from_muxed_address` | 23 | Returns the address corresponding to the provided MuxedAddressObject as a new AddressObject. Note, that MuxedAddressObject consists of the address and multiplexing id, so this conversion just strips the multiplexing id from the input muxed address. |
| `a::5` | `address.get_id_from_muxed_address` | 23 | Returns the multiplexing id corresponding to the provided MuxedAddressObject as a U64Val. |
| `a::8` | `address.muxed_address_to_strkey` | 26 | Converts a provided AddressObject or MuxedAddressObject to Stellar strkey format ('G...' for account, 'M...' for muxed account, or 'C...' for contract). Prefer directly using the Address objects whenever possible. This is only useful in the context of custom messaging protocols (e.g. cross-chain). |
| `a::7` | `address.strkey_to_muxed_address` | 26 | Converts a provided Stellar strkey address of an account, muxed account, or a contract ('G...', 'M...' or 'C...' key respectively) to an AddressObject or MuxedAddressObject (for 'M...' keys). `strkey` can be either `BytesObject` or `StringObject` (the contents should represent the base32 strkey in both cases). Any other valid or invalid strkey (e.g. 'S...') will trigger an error. Prefer directly using the Address objects whenever possible. This is only useful in the context of custom messaging protocols (e.g. cross-chain). |
| `a::a` | `address.delegate_account_auth` | 27 | Delegates the custom account authentication to the provided address. This is only available when called within `__check_auth` contract function inside a custom account. This call will require the `address` to have authorized exactly the same call tree as the one being authorized by the current `__check_auth` call. Specifically, the same signature payload and the same context will be passed into `address`s authorization check. Panics if the call has not been authorized, or if called not from within `__check_auth`. |
| `a::9` | `address.get_delegated_signers_for_current_auth_check` | 27 | Returns a vector of `Address`es of all the delegated signers that have attached signatures to authorize the current account contract invocation. **Important**: These are user-provided inputs and should be treated accordingly, in a similar fashion to the actual signatures. Specifically, the account contract must ensure that these signers actually belong to it, and perform authentication for every one of them via `delegate_account_auth`. This may only be called within `__check_auth` contract function inside a custom account. |

## PRNG

| Wire Import | Capability ID | Min Protocol | Description |
| --- | --- | --- | --- |
| `p::0` | `prng.prng_bytes_new` | 20 | Construct a new BytesObject of the given length filled with bytes drawn from the frame-local PRNG. |
| `p::_` | `prng.prng_reseed` | 20 | Reseed the frame-local PRNG with a given BytesObject, which should be 32 bytes long. |
| `p::1` | `prng.prng_u64_in_inclusive_range` | 20 | Return a u64 uniformly sampled from the inclusive range [lo,hi] by the frame-local PRNG. |
| `p::2` | `prng.prng_vec_shuffle` | 20 | Return a (Fisher-Yates) shuffled clone of a given vector, using the frame-local PRNG. |

