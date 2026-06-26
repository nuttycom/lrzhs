//! Minimal FFI bindings for Zcash address validation.
//!
//! This library exposes only the functionality needed by the Haskell FFI:
//! - `lrzhs_is_valid_shielded_address`: Validates shielded addresses (Sapling or
//!   Unified addresses containing shielded receivers)

use std::ffi::{c_char, CStr, CString};

use zcash_address::unified::Container;
use zcash_address::{ConversionError, TryFromAddress, ZcashAddress};
use zcash_protocol::consensus::NetworkType;

/// Helper to convert FFI results, returning a default value on error.
fn unwrap_exc_or<T>(exc: Result<T, ()>, def: T) -> T {
    match exc {
        Ok(value) => value,
        Err(_) => def,
    }
}

/// Returns the length of the last error message to be logged.
#[no_mangle]
pub extern "C" fn lrzhs_last_error_length() -> i32 {
    ffi_helpers::error_handling::last_error_length()
}

/// Copies the last error message into the provided allocated buffer.
///
/// # Safety
///
/// - `buf` must be non-null and point to an allocated buffer of at least `length` bytes with alignment
///   of `1`.
/// - The memory referenced by `buf` must not be mutated for the duration of the function call.
/// - The total size `length` must be no larger than `isize::MAX`.
#[no_mangle]
pub unsafe extern "C" fn lrzhs_error_message_utf8(buf: *mut c_char, length: i32) -> i32 {
    unsafe { ffi_helpers::error_handling::error_message_utf8(buf, length) }
}

/// Clears the record of the last error message.
#[no_mangle]
pub extern "C" fn lrzhs_clear_last_error() {
    ffi_helpers::error_handling::clear_last_error()
}

/// Parse a network ID (0 = Testnet, 1 = Mainnet) into the network type.
fn parse_network(value: u32) -> Result<NetworkType, ()> {
    match value {
        0 => Ok(NetworkType::Test),
        1 => Ok(NetworkType::Main),
        _ => {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                "Invalid network type: {}. Expected either 0 or 1 for Testnet or Mainnet, respectively.",
                value
            ));
            Err(())
        }
    }
}

/// A visitor type that checks if an address contains shielded receivers.
/// Returns true for Sapling addresses and Unified addresses that contain
/// at least one Sapling or Orchard receiver.
struct ShieldedAddressCheck(bool);

impl TryFromAddress for ShieldedAddressCheck {
    type Error = ();

    fn try_from_sapling(
        _network: NetworkType,
        _data: [u8; 43],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(ShieldedAddressCheck(true))
    }

    fn try_from_unified(
        _network: NetworkType,
        data: zcash_address::unified::Address,
    ) -> Result<Self, ConversionError<Self::Error>> {
        // Check if the unified address contains any shielded receivers
        let has_shielded = data.items().iter().any(|item| {
            matches!(
                item,
                zcash_address::unified::Receiver::Sapling(_)
                    | zcash_address::unified::Receiver::Orchard(_)
            )
        });
        Ok(ShieldedAddressCheck(has_shielded))
    }
}

/// Check if an address is a valid shielded address for the given network.
/// This includes Sapling addresses and Unified addresses that contain
/// Sapling or Orchard receivers.
fn is_valid_shielded_address(address: &str, expected_network: NetworkType) -> bool {
    match ZcashAddress::try_from_encoded(address) {
        Ok(addr) => {
            match addr.convert_if_network::<ShieldedAddressCheck>(expected_network) {
                Ok(ShieldedAddressCheck(has_shielded)) => has_shielded,
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

/// Returns true when the provided address decodes to a valid shielded payment address for the
/// specified network, false in any other case.
///
/// A shielded address is one of:
/// - A Sapling address
/// - A Unified address containing at least one Sapling or Orchard receiver
///
/// # Safety
///
/// - `address` must be non-null and must point to a null-terminated UTF-8 string.
/// - The memory referenced by `address` must not be mutated for the duration of the function call.
#[no_mangle]
pub unsafe extern "C" fn lrzhs_is_valid_shielded_address(
    address: *const c_char,
    network_id: u32,
) -> bool {
    let res = std::panic::catch_unwind(|| {
        let addr_network = parse_network(network_id)?;
        let addr = match unsafe { CStr::from_ptr(address) }.to_str() {
            Ok(s) => s,
            Err(e) => {
                ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                    "Invalid UTF-8 in address: {}",
                    e
                ));
                return Err(());
            }
        };
        Ok(is_valid_shielded_address(addr, addr_network))
    });

    match res {
        Ok(inner) => unwrap_exc_or(inner, false),
        Err(_) => {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!("Panic occurred"));
            false
        }
    }
}

/// Derive a fresh Orchard-only Unified Address from a ZIP-316 Unified Incoming
/// Viewing Key at the given 88-bit diversifier index.
///
/// `uivk` is a NUL-terminated `uivk1…` string. `diversifier_index` points to
/// exactly 11 bytes. `network_id`: 0 = Testnet, 1 = Mainnet; it must match the
/// network encoded in the UIVK.
///
/// Returns a newly allocated `u1…` C string (free with `lrzhs_string_free`), or
/// NULL on error (details via `lrzhs_last_error_*`).
///
/// # Safety
/// `uivk` must be a valid NUL-terminated string; `diversifier_index` must point
/// to at least 11 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lrzhs_derive_orchard_address(
    uivk: *const c_char,
    diversifier_index: *const u8,
    network_id: u32,
) -> *mut c_char {
    use orchard::keys::IncomingViewingKey as OrchardIvk;
    use zcash_address::unified::{
        Address as UnifiedAddress, Container, Encoding, Ivk, Receiver, Uivk,
    };

    let res = std::panic::catch_unwind(|| {
        if uivk.is_null() || diversifier_index.is_null() {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                "null pointer argument"
            ));
            return Err(());
        }
        let expected_network = parse_network(network_id)?;

        let uivk_str = match unsafe { CStr::from_ptr(uivk) }.to_str() {
            Ok(s) => s,
            Err(e) => {
                ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                    "Invalid UTF-8 in UIVK: {}",
                    e
                ));
                return Err(());
            }
        };

        // Reading exactly 11 bytes makes the try_into total; the arm is defensive.
        let index_bytes: [u8; 11] =
            unsafe { std::slice::from_raw_parts(diversifier_index, 11) }
                .try_into()
                .map_err(|_| {
                    ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                        "Invalid diversifier index (expected 11 bytes)"
                    ));
                })?;

        let (net, parsed) = Uivk::decode(uivk_str).map_err(|e| {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                "Failed to decode UIVK: {}",
                e
            ));
        })?;

        if net != expected_network {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                "UIVK network does not match requested network"
            ));
            return Err(());
        }

        let orchard_ivk_bytes: [u8; 64] = parsed
            .items()
            .into_iter()
            .find_map(|item| match item {
                Ivk::Orchard(data) => Some(data),
                _ => None,
            })
            .ok_or_else(|| {
                ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                    "UIVK has no Orchard receiver"
                ));
            })?;

        let ivk = OrchardIvk::from_bytes(&orchard_ivk_bytes)
            .into_option()
            .ok_or_else(|| {
                ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                    "Invalid Orchard incoming viewing key bytes"
                ));
            })?;

        let receiver = ivk.address_at(index_bytes).to_raw_address_bytes();

        let ua = UnifiedAddress::try_from_items(vec![Receiver::Orchard(receiver)])
            .map_err(|e| {
                ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                    "Failed to build unified address: {}",
                    e
                ));
            })?
            .encode(&net);

        let cstr = CString::new(ua).map_err(|e| {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                "Invalid address string: {}",
                e
            ));
        })?;
        Ok(cstr.into_raw())
    });

    match res {
        Ok(inner) => unwrap_exc_or(inner, std::ptr::null_mut()),
        Err(_) => {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!("Panic occurred"));
            std::ptr::null_mut()
        }
    }
}

/// Free a string previously returned by an lrzhs function.
///
/// # Safety
/// `s` must be a pointer returned by this library, or NULL.
#[no_mangle]
pub unsafe extern "C" fn lrzhs_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(unsafe { CString::from_raw(s) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_address::unified::{Address, Encoding};
    use zcash_address::ToAddress;

    /// Test vector from zcash-test-vectors unified_address.rs
    /// This is the first test vector with both Sapling and Orchard receivers
    const TEST_UNIFIED_ADDRESS: &str = "u1l8xunezsvhq8fgzfl7404m450nwnd76zshscn6nfys7vyz2ywyh4cc5daaq0c7q2su5lqfh23sp7fkf3kt27ve5948mzpfdvckzaect2jtte308mkwlycj2u0eac077wu70vqcetkxf";

    fn extract_sapling_address_from_ua(ua_str: &str) -> Option<String> {
        let (network, ua) = Address::decode(ua_str).ok()?;
        for item in ua.items() {
            if let zcash_address::unified::Receiver::Sapling(data) = item {
                let sapling_addr = ZcashAddress::from_sapling(network, data);
                return Some(sapling_addr.encode());
            }
        }
        None
    }

    #[test]
    fn test_valid_unified_address_with_shielded_receivers() {
        // This UA contains both Sapling and Orchard receivers
        assert!(is_valid_shielded_address(TEST_UNIFIED_ADDRESS, NetworkType::Main));
    }

    #[test]
    fn test_valid_sapling_address_extracted_from_ua() {
        // Extract the Sapling address from the unified address
        let sapling_addr = extract_sapling_address_from_ua(TEST_UNIFIED_ADDRESS)
            .expect("Test UA should contain a Sapling receiver");

        // Verify it starts with the correct prefix
        assert!(sapling_addr.starts_with("zs1"), "Expected mainnet Sapling address, got: {}", sapling_addr);

        // Verify it validates correctly
        assert!(is_valid_shielded_address(&sapling_addr, NetworkType::Main));
    }

    #[test]
    fn test_sapling_address_wrong_network() {
        let sapling_addr = extract_sapling_address_from_ua(TEST_UNIFIED_ADDRESS)
            .expect("Test UA should contain a Sapling receiver");

        // Mainnet address should fail on testnet
        assert!(!is_valid_shielded_address(&sapling_addr, NetworkType::Test));
    }

    #[test]
    fn test_unified_address_wrong_network() {
        // Mainnet UA should fail on testnet
        assert!(!is_valid_shielded_address(TEST_UNIFIED_ADDRESS, NetworkType::Test));
    }

    #[test]
    fn test_invalid_address() {
        assert!(!is_valid_shielded_address("not_a_valid_address", NetworkType::Main));
    }

    #[test]
    fn test_transparent_address_returns_false() {
        // Transparent addresses should return false (no shielded receivers)
        let addr = "t1VShHAhsQc5RVndQLyM3G97RgvPBYdWLxe";
        assert!(!is_valid_shielded_address(addr, NetworkType::Main));
    }

    #[test]
    fn test_empty_address_returns_false() {
        assert!(!is_valid_shielded_address("", NetworkType::Main));
    }
}

#[cfg(test)]
mod derive_tests {
    use super::*;
    use orchard::keys::{FullViewingKey, SpendingKey};
    use std::ffi::{CStr, CString};
    use zcash_address::unified::{Address, Encoding, Ivk, Receiver, Uivk};
    use zcash_protocol::consensus::NetworkType;
    use zip32::Scope;

    fn mainnet_uivk(seed: u8) -> (String, orchard::keys::IncomingViewingKey) {
        let sk = SpendingKey::from_bytes([seed; 32]).unwrap();
        let ivk = FullViewingKey::from(&sk).to_ivk(Scope::External);
        let uivk = Uivk::try_from_items(vec![Ivk::Orchard(ivk.to_bytes())])
            .unwrap()
            .encode(&NetworkType::Main);
        (uivk, ivk)
    }

    fn call(uivk: &str, index: [u8; 11], network_id: u32) -> Option<String> {
        let c = CString::new(uivk).unwrap();
        let ptr = unsafe { lrzhs_derive_orchard_address(c.as_ptr(), index.as_ptr(), network_id) };
        if ptr.is_null() {
            None
        } else {
            let s = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap().to_owned();
            unsafe { lrzhs_string_free(ptr) };
            Some(s)
        }
    }

    #[test]
    fn derives_expected_orchard_only_address() {
        let (uivk, ivk) = mainnet_uivk(7);
        let index = [0u8; 11];
        let expected = Address::try_from_items(vec![Receiver::Orchard(
            ivk.address_at(index).to_raw_address_bytes(),
        )])
        .unwrap()
        .encode(&NetworkType::Main);
        assert_eq!(call(&uivk, index, 1), Some(expected));
    }

    #[test]
    fn distinct_indices_give_distinct_addresses() {
        let (uivk, _) = mainnet_uivk(7);
        assert!(call(&uivk, [0u8; 11], 1) != call(&uivk, [9u8; 11], 1));
    }

    #[test]
    fn rejects_invalid_uivk() {
        assert_eq!(call("not-a-uivk", [0u8; 11], 1), None);
    }

    #[test]
    fn rejects_network_mismatch() {
        let (uivk, _) = mainnet_uivk(7);
        assert_eq!(call(&uivk, [0u8; 11], 0), None);
    }

    #[test]
    fn rejects_null_uivk() {
        let index = [0u8; 11];
        let ptr = unsafe { lrzhs_derive_orchard_address(std::ptr::null(), index.as_ptr(), 1) };
        assert!(ptr.is_null());
    }
}
