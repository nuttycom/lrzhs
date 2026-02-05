//! FFI bindings for Zcash light client functionality.
//!
//! This library exposes the zcash_client_backend and zcash_client_sqlite
//! functionality through a C FFI for use by Haskell.

use std::ffi::{c_char, CStr, CString};
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};

use rand::rngs::OsRng;
use uuid::Uuid;

// Re-exports from zcash_client_backend and its dependencies
use zcash_client_backend::data_api::chain::ChainState;
use zcash_client_backend::data_api::scanning::ScanPriority;
use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;
use zcash_client_backend::data_api::{
    Account, AccountBirthday, AccountPurpose, AccountSource, WalletRead, WalletWrite,
    Zip32Derivation,
};
use zcash_client_backend::keys::UnifiedFullViewingKey;

use zcash_client_sqlite::util::SystemClock;
use zcash_client_sqlite::wallet::init::init_wallet_db;
use zcash_client_sqlite::{AccountUuid, WalletDb};

// These types come from the re-exported versions via zcash_client_backend
use zcash_client_backend::keys::UnifiedAddressRequest;

// Tree reading for account birthday parsing
use zcash_primitives::merkle_tree::read_commitment_tree;
use sapling::NOTE_COMMITMENT_TREE_DEPTH as SAPLING_DEPTH;
use orchard::NOTE_COMMITMENT_TREE_DEPTH as ORCHARD_DEPTH;
use orchard::tree::MerkleHashOrchard;
use sapling::Node as SaplingNode;

mod ffi;

use ffi::*;

use secrecy::SecretVec;

// ============================================================================
// Global Initialization
// ============================================================================

static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize the library with optional logging.
#[no_mangle]
pub extern "C" fn lrzhs_init_on_load(log_level: u8) {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let level = match log_level {
        0 => tracing::Level::ERROR,
        1 => tracing::Level::ERROR,
        2 => tracing::Level::WARN,
        3 => tracing::Level::INFO,
        4 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };

    let subscriber = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(true)
        .finish();

    let _ = tracing::subscriber::set_global_default(subscriber);
}

// ============================================================================
// Error Handling
// ============================================================================

fn unwrap_exc_or<T>(exc: Result<T, ()>, def: T) -> T {
    match exc {
        Ok(value) => value,
        Err(_) => def,
    }
}

#[no_mangle]
pub extern "C" fn lrzhs_last_error_length() -> i32 {
    ffi_helpers::error_handling::last_error_length()
}

#[no_mangle]
pub unsafe extern "C" fn lrzhs_error_message_utf8(buf: *mut c_char, length: i32) -> i32 {
    unsafe { ffi_helpers::error_handling::error_message_utf8(buf, length) }
}

#[no_mangle]
pub extern "C" fn lrzhs_clear_last_error() {
    ffi_helpers::error_handling::clear_last_error()
}

// ============================================================================
// Network Helpers
// ============================================================================

use zcash_primitives::block::BlockHash;
use zcash_primitives::consensus::{BlockHeight, MainNetwork, NetworkType, Parameters, TestNetwork};

#[derive(Clone, Copy)]
pub enum Network {
    Main,
    Test,
}

impl Parameters for Network {
    fn network_type(&self) -> NetworkType {
        match self {
            Network::Main => NetworkType::Main,
            Network::Test => NetworkType::Test,
        }
    }

    fn activation_height(
        &self,
        nu: zcash_primitives::consensus::NetworkUpgrade,
    ) -> Option<BlockHeight> {
        match self {
            Network::Main => MainNetwork.activation_height(nu),
            Network::Test => TestNetwork.activation_height(nu),
        }
    }
}

fn parse_network(value: u32) -> Result<Network, ()> {
    match value {
        0 => Ok(Network::Test),
        1 => Ok(Network::Main),
        _ => {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                "Invalid network type: {}",
                value
            ));
            Err(())
        }
    }
}

fn parse_network_type(value: u32) -> Result<NetworkType, ()> {
    match value {
        0 => Ok(NetworkType::Test),
        1 => Ok(NetworkType::Main),
        _ => {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                "Invalid network type: {}",
                value
            ));
            Err(())
        }
    }
}

// Helper to open a wallet database
fn open_wallet_db(
    db_path: &str,
    network: Network,
) -> Result<WalletDb<rusqlite::Connection, Network, SystemClock, OsRng>, ()> {
    WalletDb::for_path(db_path, network, SystemClock, OsRng).map_err(|e| {
        ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
            "Failed to open wallet database: {}",
            e
        ));
    })
}

// Helper to parse tree state from FFI parameters into ChainState.
//
// The tree bytes should be raw binary (not hex-encoded) commitment tree data
// in the legacy format used by lightwalletd's TreeState.
fn parse_chain_state(
    height: u32,
    hash: *const u8,
    _time: u32,
    sapling_tree: *const u8,
    sapling_tree_len: usize,
    orchard_tree: *const u8,
    orchard_tree_len: usize,
) -> Result<ChainState, ()> {
    // Parse block hash (required, 32 bytes)
    let block_hash = if hash.is_null() {
        ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
            "Block hash is required for tree state"
        ));
        return Err(());
    } else {
        let hash_bytes: [u8; 32] = unsafe { std::slice::from_raw_parts(hash, 32) }
            .try_into()
            .map_err(|_| {
                ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                    "Invalid block hash length"
                ));
            })?;
        BlockHash(hash_bytes)
    };

    // Parse Sapling commitment tree and convert to frontier
    let sapling_frontier = if sapling_tree.is_null() || sapling_tree_len == 0 {
        incrementalmerkletree::frontier::Frontier::empty()
    } else {
        let bytes = unsafe { std::slice::from_raw_parts(sapling_tree, sapling_tree_len) };
        let tree = read_commitment_tree::<SaplingNode, _, SAPLING_DEPTH>(bytes).map_err(|e| {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                "Failed to parse Sapling commitment tree: {}",
                e
            ));
        })?;
        tree.to_frontier()
    };

    // Parse Orchard commitment tree and convert to frontier
    let orchard_frontier = if orchard_tree.is_null() || orchard_tree_len == 0 {
        incrementalmerkletree::frontier::Frontier::empty()
    } else {
        let bytes = unsafe { std::slice::from_raw_parts(orchard_tree, orchard_tree_len) };
        let tree =
            read_commitment_tree::<MerkleHashOrchard, _, { ORCHARD_DEPTH as u8 }>(bytes).map_err(
                |e| {
                    ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                        "Failed to parse Orchard commitment tree: {}",
                        e
                    ));
                },
            )?;
        tree.to_frontier()
    };

    Ok(ChainState::new(
        BlockHeight::from_u32(height),
        block_hash,
        sapling_frontier,
        orchard_frontier,
    ))
}

// ============================================================================
// Address Validation
// ============================================================================

use zcash_address::unified::Container;
use zcash_address::{ConversionError, TryFromAddress, ZcashAddress};

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

fn is_valid_shielded_address(address: &str, expected_network: NetworkType) -> bool {
    match ZcashAddress::try_from_encoded(address) {
        Ok(addr) => match addr.convert_if_network::<ShieldedAddressCheck>(expected_network) {
            Ok(ShieldedAddressCheck(has_shielded)) => has_shielded,
            Err(_) => false,
        },
        Err(_) => false,
    }
}

#[no_mangle]
pub unsafe extern "C" fn lrzhs_is_valid_shielded_address(
    address: *const c_char,
    network_id: u32,
) -> bool {
    let res = std::panic::catch_unwind(|| {
        let addr_network = parse_network_type(network_id)?;
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

// ============================================================================
// Database Initialization
// ============================================================================

#[no_mangle]
pub unsafe extern "C" fn lrzhs_init_data_database(
    db_data: *const u8,
    db_data_len: usize,
    seed: *const u8,
    seed_len: usize,
    network_id: u32,
) -> i32 {
    let res = std::panic::catch_unwind(|| {
        let network = parse_network(network_id)?;

        let db_path = unsafe {
            let slice = std::slice::from_raw_parts(db_data, db_data_len);
            std::str::from_utf8(slice).map_err(|e| {
                ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                    "Invalid UTF-8 in database path: {}",
                    e
                ));
            })?
        };

        let seed_secret: Option<SecretVec<u8>> = if seed.is_null() || seed_len == 0 {
            None
        } else {
            Some(SecretVec::new(
                unsafe { std::slice::from_raw_parts(seed, seed_len) }.to_vec(),
            ))
        };

        let mut db = open_wallet_db(db_path, network)?;

        init_wallet_db(&mut db, seed_secret).map_err(|e| {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                "Failed to initialize wallet database: {}",
                e
            ));
        })?;

        Ok(0i32)
    });

    match res {
        Ok(inner) => unwrap_exc_or(inner, 2),
        Err(_) => {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!("Panic occurred"));
            2
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn lrzhs_init_block_metadata_db(
    fs_block_db_root: *const u8,
    fs_block_db_root_len: usize,
) -> bool {
    let res = std::panic::catch_unwind(|| {
        let db_path = unsafe {
            let slice = std::slice::from_raw_parts(fs_block_db_root, fs_block_db_root_len);
            std::str::from_utf8(slice).map_err(|e| {
                ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                    "Invalid UTF-8 in database path: {}",
                    e
                ));
            })?
        };

        // Create the directory if it doesn't exist
        std::fs::create_dir_all(db_path).map_err(|e| {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                "Failed to create block cache directory: {}",
                e
            ));
        })?;

        Ok(true)
    });

    match res {
        Ok(inner) => unwrap_exc_or(inner, false),
        Err(_) => {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!("Panic occurred"));
            false
        }
    }
}

// ============================================================================
// Wallet Handle Management
// ============================================================================

/// Opens a wallet database and returns an opaque handle.
///
/// The handle should be passed to subsequent wallet operations and must be
/// closed with `lrzhs_close_wallet` when no longer needed.
///
/// # Safety
/// - `db_data` must be a valid pointer to a UTF-8 encoded path string.
/// - The caller must eventually call `lrzhs_close_wallet` to free the handle.
///
/// # Returns
/// A pointer to a `DbHandle` on success, or null on failure.
/// Call `lrzhs_last_error_length` and `lrzhs_error_message_utf8` to get error details.
#[no_mangle]
pub unsafe extern "C" fn lrzhs_open_wallet(
    db_data: *const u8,
    db_data_len: usize,
    network_id: u32,
) -> *mut ffi::DbHandle {
    let res = std::panic::catch_unwind(|| {
        let network = parse_network(network_id)?;

        let db_path = unsafe {
            let slice = std::slice::from_raw_parts(db_data, db_data_len);
            std::str::from_utf8(slice).map_err(|e| {
                ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                    "Invalid UTF-8 in database path: {}",
                    e
                ));
            })?
        };

        let db = open_wallet_db(db_path, network)?;

        Ok(Box::into_raw(Box::new(ffi::DbHandle { db, network })))
    });

    match res {
        Ok(inner) => unwrap_exc_or(inner, std::ptr::null_mut()),
        Err(_) => {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!("Panic occurred"));
            std::ptr::null_mut()
        }
    }
}

// ============================================================================
// Account Management
// ============================================================================

use zip32::fingerprint::SeedFingerprint;
use zcash_keys::keys::Era;

#[no_mangle]
pub unsafe extern "C" fn lrzhs_create_account(
    handle: *mut ffi::DbHandle,
    seed: *const u8,
    seed_len: usize,
    treestate_height: u32,
    treestate_hash: *const u8,
    treestate_time: u32,
    treestate_sapling_tree: *const u8,
    treestate_sapling_tree_len: usize,
    treestate_orchard_tree: *const u8,
    treestate_orchard_tree_len: usize,
    recover_until: i64,
    account_name: *const c_char,
    key_source: *const c_char,
) -> *mut FfiCreateAccountResult {
    let res = std::panic::catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                "Wallet handle is null"
            ));
            return Err(());
        }

        let db_handle = unsafe { &mut *handle };

        if seed.is_null() || seed_len == 0 {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!("Seed is required"));
            return Err(());
        }

        let seed_secret =
            SecretVec::new(unsafe { std::slice::from_raw_parts(seed, seed_len) }.to_vec());

        // Parse the tree state for the account birthday
        let prior_chain_state = parse_chain_state(
            treestate_height.saturating_sub(1),
            treestate_hash,
            treestate_time,
            treestate_sapling_tree,
            treestate_sapling_tree_len,
            treestate_orchard_tree,
            treestate_orchard_tree_len,
        )?;

        let recover_until_height = if recover_until >= 0 {
            Some(BlockHeight::from_u32(recover_until as u32))
        } else {
            None
        };

        let birthday = AccountBirthday::from_parts(prior_chain_state, recover_until_height);

        let name = if account_name.is_null() {
            String::new()
        } else {
            unsafe { CStr::from_ptr(account_name) }
                .to_str()
                .unwrap_or("")
                .to_string()
        };

        let key_src = if key_source.is_null() {
            None
        } else {
            Some(
                unsafe { CStr::from_ptr(key_source) }
                    .to_str()
                    .unwrap_or("")
                    .to_string(),
            )
        };

        let (account_id, usk) = db_handle
            .db
            .create_account(&name, &seed_secret, &birthday, key_src.as_deref())
            .map_err(|e| {
                ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                    "Failed to create account: {}",
                    e
                ));
            })?;

        let usk_bytes = usk.to_bytes(Era::Orchard);
        let usk_len = usk_bytes.len();
        let usk_ptr = {
            let mut v = usk_bytes.to_vec();
            let ptr = v.as_mut_ptr();
            std::mem::forget(v);
            ptr
        };

        let account_uuid = db_handle
            .db
            .get_account(account_id)
            .map_err(|e| {
                ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                    "Failed to get account: {}",
                    e
                ));
            })?
            .ok_or_else(|| {
                ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                    "Account not found after creation"
                ));
            })?
            .id();

        Ok(Box::into_raw(Box::new(FfiCreateAccountResult {
            uuid: FfiUuid::from_account_uuid(account_uuid),
            usk: usk_ptr,
            usk_len,
        })))
    }));

    match res {
        Ok(inner) => unwrap_exc_or(inner, std::ptr::null_mut()),
        Err(_) => {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!("Panic occurred"));
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn lrzhs_import_account_ufvk(
    handle: *mut ffi::DbHandle,
    ufvk: *const c_char,
    treestate_height: u32,
    treestate_hash: *const u8,
    treestate_time: u32,
    treestate_sapling_tree: *const u8,
    treestate_sapling_tree_len: usize,
    treestate_orchard_tree: *const u8,
    treestate_orchard_tree_len: usize,
    recover_until: i64,
    spending: bool,
    account_name: *const c_char,
    key_source: *const c_char,
    seed_fingerprint: *const u8,
    hd_account_index: u32,
) -> *mut FfiUuid {
    let res = std::panic::catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                "Wallet handle is null"
            ));
            return Err(());
        }

        let db_handle = unsafe { &mut *handle };

        let ufvk_str = if ufvk.is_null() {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!("UFVK is required"));
            return Err(());
        } else {
            unsafe { CStr::from_ptr(ufvk) }.to_str().map_err(|e| {
                ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                    "Invalid UTF-8 in UFVK: {}",
                    e
                ));
            })?
        };

        let ufvk_parsed =
            UnifiedFullViewingKey::decode(&db_handle.network, ufvk_str).map_err(|e| {
                ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                    "Failed to decode UFVK: {}",
                    e
                ));
            })?;

        // Parse the tree state for the account birthday
        let prior_chain_state = parse_chain_state(
            treestate_height.saturating_sub(1),
            treestate_hash,
            treestate_time,
            treestate_sapling_tree,
            treestate_sapling_tree_len,
            treestate_orchard_tree,
            treestate_orchard_tree_len,
        )?;

        let recover_until_height = if recover_until >= 0 {
            Some(BlockHeight::from_u32(recover_until as u32))
        } else {
            None
        };

        let birthday = AccountBirthday::from_parts(prior_chain_state, recover_until_height);

        let name = if account_name.is_null() {
            String::new()
        } else {
            unsafe { CStr::from_ptr(account_name) }
                .to_str()
                .unwrap_or("")
                .to_string()
        };

        let key_src = if key_source.is_null() {
            None
        } else {
            Some(
                unsafe { CStr::from_ptr(key_source) }
                    .to_str()
                    .unwrap_or("")
                    .to_string(),
            )
        };

        // Parse derivation info if seed fingerprint is provided
        let derivation = if !seed_fingerprint.is_null() {
            let fp_bytes: [u8; 32] = unsafe { std::slice::from_raw_parts(seed_fingerprint, 32) }
                .try_into()
                .map_err(|_| {
                    ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                        "Invalid seed fingerprint length"
                    ));
                })?;
            let fp = SeedFingerprint::from_bytes(fp_bytes);
            let account_id = zip32::AccountId::try_from(hd_account_index).map_err(|_| {
                ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                    "Invalid HD account index"
                ));
            })?;
            Some(Zip32Derivation::new(fp, account_id))
        } else {
            None
        };

        let purpose = if spending {
            AccountPurpose::Spending { derivation }
        } else {
            AccountPurpose::ViewOnly
        };

        let account = db_handle
            .db
            .import_account_ufvk(&name, &ufvk_parsed, &birthday, purpose, key_src.as_deref())
            .map_err(|e| {
                ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                    "Failed to import account: {}",
                    e
                ));
            })?;

        Ok(Box::into_raw(Box::new(FfiUuid::from_account_uuid(account.id()))))
    }));

    match res {
        Ok(inner) => unwrap_exc_or(inner, std::ptr::null_mut()),
        Err(_) => {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!("Panic occurred"));
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn lrzhs_list_accounts(
    handle: *mut ffi::DbHandle,
) -> *mut FfiAccounts {
    let res = std::panic::catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                "Wallet handle is null"
            ));
            return Err(());
        }

        let db_handle = unsafe { &*handle };

        let accounts = db_handle.db.get_account_ids().map_err(|e| {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                "Failed to list accounts: {}",
                e
            ));
        })?;

        let uuids: Vec<FfiUuid> = accounts.into_iter().map(FfiUuid::from_account_uuid).collect();

        let len = uuids.len();
        let ptr = if len > 0 {
            let mut uuids = uuids;
            let ptr = uuids.as_mut_ptr();
            std::mem::forget(uuids);
            ptr
        } else {
            std::ptr::null_mut()
        };

        Ok(Box::into_raw(Box::new(FfiAccounts {
            accounts: ptr,
            len,
        })))
    }));

    match res {
        Ok(inner) => unwrap_exc_or(inner, std::ptr::null_mut()),
        Err(_) => {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!("Panic occurred"));
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn lrzhs_get_account(
    handle: *mut ffi::DbHandle,
    account_uuid_bytes: *const u8,
) -> *mut FfiAccount {
    let res = std::panic::catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                "Wallet handle is null"
            ));
            return Err(());
        }

        let db_handle = unsafe { &*handle };

        let account_uuid = if account_uuid_bytes.is_null() {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                "Account UUID is required"
            ));
            return Err(());
        } else {
            let bytes: [u8; 16] = unsafe { std::slice::from_raw_parts(account_uuid_bytes, 16) }
                .try_into()
                .map_err(|_| {
                    ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                        "Invalid UUID bytes"
                    ));
                })?;
            AccountUuid::from_uuid(Uuid::from_bytes(bytes))
        };

        let account = db_handle.db.get_account(account_uuid).map_err(|e| {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                "Failed to get account: {}",
                e
            ));
        })?;

        match account {
            Some(acc) => {
                let name_str = acc.name().unwrap_or("");
                let name_cstr = CString::new(name_str).unwrap();
                let name_ptr = name_cstr.into_raw();

                let key_source_ptr = match acc.source() {
                    AccountSource::Derived { key_source, .. } => key_source
                        .as_ref()
                        .map(|s| CString::new(s.clone()).unwrap().into_raw())
                        .unwrap_or(std::ptr::null_mut()),
                    AccountSource::Imported { key_source, .. } => key_source
                        .as_ref()
                        .map(|s| CString::new(s.clone()).unwrap().into_raw())
                        .unwrap_or(std::ptr::null_mut()),
                };

                let ufvk_ptr = acc
                    .ufvk()
                    .map(|ufvk| CString::new(ufvk.encode(&db_handle.network)).unwrap().into_raw())
                    .unwrap_or(std::ptr::null_mut());

                // uivk() returns UnifiedIncomingViewingKey directly (not Option)
                let uivk = acc.uivk();
                let uivk_ptr = CString::new(uivk.encode(&db_handle.network))
                    .unwrap()
                    .into_raw();

                let has_spend_key = matches!(acc.source(), AccountSource::Derived { .. });

                Ok(Box::into_raw(Box::new(FfiAccount {
                    uuid: FfiUuid::from_account_uuid(acc.id()),
                    name: name_ptr,
                    key_source: key_source_ptr,
                    ufvk: ufvk_ptr,
                    uivk: uivk_ptr,
                    has_spend_key,
                })))
            }
            None => Ok(std::ptr::null_mut()),
        }
    }));

    match res {
        Ok(inner) => unwrap_exc_or(inner, std::ptr::null_mut()),
        Err(_) => {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!("Panic occurred"));
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn lrzhs_seed_fingerprint(
    seed: *const u8,
    seed_len: usize,
    output: *mut u8,
) -> bool {
    let res = std::panic::catch_unwind(|| {
        if seed.is_null() || seed_len == 0 {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!("Seed is required"));
            return Err(());
        }

        if output.is_null() {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                "Output buffer is required"
            ));
            return Err(());
        }

        let seed_bytes = unsafe { std::slice::from_raw_parts(seed, seed_len) };

        let fingerprint = SeedFingerprint::from_seed(seed_bytes);
        match fingerprint {
            Some(fp) => {
                unsafe {
                    std::ptr::copy_nonoverlapping(fp.to_bytes().as_ptr(), output, 32);
                }
                Ok(true)
            }
            None => {
                ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                    "Failed to compute seed fingerprint"
                ));
                Err(())
            }
        }
    });

    match res {
        Ok(inner) => unwrap_exc_or(inner, false),
        Err(_) => {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!("Panic occurred"));
            false
        }
    }
}

// ============================================================================
// Address Generation
// ============================================================================

#[no_mangle]
pub unsafe extern "C" fn lrzhs_get_current_address(
    handle: *mut ffi::DbHandle,
    account_uuid_bytes: *const u8,
) -> *mut c_char {
    let res = std::panic::catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                "Wallet handle is null"
            ));
            return Err(());
        }

        let db_handle = unsafe { &*handle };

        let account_uuid = if account_uuid_bytes.is_null() {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                "Account UUID is required"
            ));
            return Err(());
        } else {
            let bytes: [u8; 16] = unsafe { std::slice::from_raw_parts(account_uuid_bytes, 16) }
                .try_into()
                .map_err(|_| {
                    ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                        "Invalid UUID bytes"
                    ));
                })?;
            AccountUuid::from_uuid(Uuid::from_bytes(bytes))
        };

        // Use get_last_generated_address_matching which returns the most recently generated address
        // Use AllAvailableKeys to get any available address
        let address = db_handle.db.get_last_generated_address_matching(account_uuid, UnifiedAddressRequest::AllAvailableKeys).map_err(|e| {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                "Failed to get current address: {}",
                e
            ));
        })?;

        match address {
            Some(addr) => {
                let addr_str = addr.encode(&db_handle.network);
                let cstr = CString::new(addr_str).map_err(|e| {
                    ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                        "Invalid address string: {}",
                        e
                    ));
                })?;
                Ok(cstr.into_raw())
            }
            None => Ok(std::ptr::null_mut()),
        }
    }));

    match res {
        Ok(inner) => unwrap_exc_or(inner, std::ptr::null_mut()),
        Err(_) => {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!("Panic occurred"));
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn lrzhs_get_next_available_address(
    handle: *mut ffi::DbHandle,
    account_uuid_bytes: *const u8,
    request: u8,
) -> *mut c_char {
    let res = std::panic::catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                "Wallet handle is null"
            ));
            return Err(());
        }

        let db_handle = unsafe { &mut *handle };

        let account_uuid = if account_uuid_bytes.is_null() {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                "Account UUID is required"
            ));
            return Err(());
        } else {
            let bytes: [u8; 16] = unsafe { std::slice::from_raw_parts(account_uuid_bytes, 16) }
                .try_into()
                .map_err(|_| {
                    ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                        "Invalid UUID bytes"
                    ));
                })?;
            AccountUuid::from_uuid(Uuid::from_bytes(bytes))
        };

        let has_sapling = (request & 0x2) != 0;
        let has_orchard = (request & 0x4) != 0;

        // Construct the UnifiedAddressRequest
        // If neither is specified, use default (all available)
        use zcash_keys::keys::ReceiverRequirement;
        let ua_request = if !has_sapling && !has_orchard {
            UnifiedAddressRequest::AllAvailableKeys
        } else {
            let orchard_req = if has_orchard {
                ReceiverRequirement::Require
            } else {
                ReceiverRequirement::Omit
            };
            let sapling_req = if has_sapling {
                ReceiverRequirement::Require
            } else {
                ReceiverRequirement::Omit
            };
            // No transparent addresses
            UnifiedAddressRequest::custom(orchard_req, sapling_req, ReceiverRequirement::Omit)
                .map_err(|_| {
                    ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                        "Invalid address request"
                    ));
                })?
        };

        let result = db_handle
            .db
            .get_next_available_address(account_uuid, ua_request)
            .map_err(|e| {
                ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                    "Failed to get next available address: {}",
                    e
                ));
            })?;

        match result {
            Some((addr, _diversifier_index)) => {
                let addr_str = addr.encode(&db_handle.network);
                let cstr = CString::new(addr_str).map_err(|e| {
                    ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                        "Invalid address string: {}",
                        e
                    ));
                })?;
                Ok(cstr.into_raw())
            }
            None => Ok(std::ptr::null_mut()),
        }
    }));

    match res {
        Ok(inner) => unwrap_exc_or(inner, std::ptr::null_mut()),
        Err(_) => {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!("Panic occurred"));
            std::ptr::null_mut()
        }
    }
}

// ============================================================================
// Wallet Summary
// ============================================================================

#[no_mangle]
pub unsafe extern "C" fn lrzhs_get_wallet_summary(
    handle: *mut ffi::DbHandle,
    _min_confirmations: u32,
) -> *mut FfiWalletSummary {
    let res = std::panic::catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                "Wallet handle is null"
            ));
            return Err(());
        }

        let db_handle = unsafe { &*handle };

        // Use the default confirmations policy for now
        let summary = db_handle.db.get_wallet_summary(ConfirmationsPolicy::default()).map_err(|e| {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                "Failed to get wallet summary: {}",
                e
            ));
        })?;

        match summary {
            Some(s) => {
                let account_balances: Vec<FfiAccountBalance> = s
                    .account_balances()
                    .iter()
                    .map(|(account_uuid, balance)| {
                        let sapling = balance.sapling_balance();
                        let orchard = balance.orchard_balance();

                        FfiAccountBalance {
                            account_uuid: FfiUuid::from_account_uuid(*account_uuid),
                            sapling_balance: FfiBalance {
                                spendable: sapling.spendable_value().into_u64() as i64,
                                change_pending: sapling.change_pending_confirmation().into_u64() as i64,
                                value_pending: sapling.value_pending_spendability().into_u64() as i64,
                            },
                            orchard_balance: FfiBalance {
                                spendable: orchard.spendable_value().into_u64() as i64,
                                change_pending: orchard.change_pending_confirmation().into_u64() as i64,
                                value_pending: orchard.value_pending_spendability().into_u64() as i64,
                            },
                        }
                    })
                    .collect();

                let account_balances_len = account_balances.len();
                let account_balances_ptr = if account_balances_len > 0 {
                    let mut balances = account_balances;
                    let ptr = balances.as_mut_ptr();
                    std::mem::forget(balances);
                    ptr
                } else {
                    std::ptr::null_mut()
                };

                let chain_tip_height: u32 = s.chain_tip_height().into();
                let fully_scanned_height: u32 = s.fully_scanned_height().into();

                // Progress.scan() returns a Ratio<u64>
                let scan_ratio = s.progress().scan();
                let scan_progress_numerator = *scan_ratio.numerator();
                let scan_progress_denominator = *scan_ratio.denominator();

                // These methods are on WalletSummary directly
                let next_sapling_subtree_index = s.next_sapling_subtree_index();
                let next_orchard_subtree_index = s.next_orchard_subtree_index();

                Ok(Box::into_raw(Box::new(FfiWalletSummary {
                    account_balances: account_balances_ptr,
                    account_balances_len,
                    chain_tip_height: chain_tip_height as i64,
                    fully_scanned_height: fully_scanned_height as i64,
                    scan_progress_numerator,
                    scan_progress_denominator,
                    next_sapling_subtree_index,
                    next_orchard_subtree_index,
                })))
            }
            None => Ok(std::ptr::null_mut()),
        }
    }));

    match res {
        Ok(inner) => unwrap_exc_or(inner, std::ptr::null_mut()),
        Err(_) => {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!("Panic occurred"));
            std::ptr::null_mut()
        }
    }
}

// ============================================================================
// Chain Synchronization
// ============================================================================

#[no_mangle]
pub unsafe extern "C" fn lrzhs_update_chain_tip(
    handle: *mut ffi::DbHandle,
    height: u32,
) -> bool {
    let res = std::panic::catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                "Wallet handle is null"
            ));
            return Err(());
        }

        let db_handle = unsafe { &mut *handle };

        db_handle
            .db
            .update_chain_tip(BlockHeight::from_u32(height))
            .map_err(|e| {
                ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                    "Failed to update chain tip: {}",
                    e
                ));
            })?;

        Ok(true)
    }));

    match res {
        Ok(inner) => unwrap_exc_or(inner, false),
        Err(_) => {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!("Panic occurred"));
            false
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn lrzhs_fully_scanned_height(
    handle: *mut ffi::DbHandle,
) -> i64 {
    let res = std::panic::catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                "Wallet handle is null"
            ));
            return Err(());
        }

        let db_handle = unsafe { &*handle };

        let height = db_handle.db.get_wallet_summary(ConfirmationsPolicy::default()).map_err(|e| {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                "Failed to get wallet summary: {}",
                e
            ));
        })?;

        match height {
            Some(s) => Ok(i64::from(u32::from(s.fully_scanned_height()))),
            None => Ok(-1i64),
        }
    }));

    match res {
        Ok(inner) => unwrap_exc_or(inner, -1i64),
        Err(_) => {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!("Panic occurred"));
            -1i64
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn lrzhs_suggest_scan_ranges(
    handle: *mut ffi::DbHandle,
) -> *mut FfiScanRanges {
    let res = std::panic::catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                "Wallet handle is null"
            ));
            return Err(());
        }

        let db_handle = unsafe { &*handle };

        let ranges = db_handle.db.suggest_scan_ranges().map_err(|e| {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!(
                "Failed to get scan ranges: {}",
                e
            ));
        })?;

        let ffi_ranges: Vec<FfiScanRange> = ranges
            .iter()
            .map(|r| FfiScanRange {
                start: i64::from(u32::from(r.block_range().start)),
                end: i64::from(u32::from(r.block_range().end)),
                priority: match r.priority() {
                    ScanPriority::Scanned => FfiScanPriority::Scanned,
                    ScanPriority::Historic => FfiScanPriority::Historic,
                    ScanPriority::OpenAdjacent => FfiScanPriority::OpenAdjacent,
                    ScanPriority::Verify => FfiScanPriority::Verify,
                    ScanPriority::FoundNote => FfiScanPriority::FoundNote,
                    ScanPriority::ChainTip => FfiScanPriority::ChainTip,
                    _ => FfiScanPriority::Scanned, // Handle any other variants
                },
            })
            .collect();

        let len = ffi_ranges.len();
        let ptr = if len > 0 {
            let mut ranges = ffi_ranges;
            let ptr = ranges.as_mut_ptr();
            std::mem::forget(ranges);
            ptr
        } else {
            std::ptr::null_mut()
        };

        Ok(Box::into_raw(Box::new(FfiScanRanges { ranges: ptr, len })))
    }));

    match res {
        Ok(inner) => unwrap_exc_or(inner, std::ptr::null_mut()),
        Err(_) => {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!("Panic occurred"));
            std::ptr::null_mut()
        }
    }
}

// ============================================================================
// Utilities
// ============================================================================

#[no_mangle]
pub extern "C" fn lrzhs_branch_id_for_height(height: u32, network_id: u32) -> u32 {
    let res = std::panic::catch_unwind(|| {
        let network = parse_network(network_id)?;
        use zcash_primitives::consensus::BranchId;
        let branch_id = BranchId::for_height(&network, BlockHeight::from_u32(height));
        Ok(u32::from(branch_id))
    });

    match res {
        Ok(inner) => unwrap_exc_or(inner, 0),
        Err(_) => {
            ffi_helpers::error_handling::update_last_error(anyhow::anyhow!("Panic occurred"));
            0
        }
    }
}

// ============================================================================
// Block Cache Operations
// ============================================================================
// NOTE: These functions require the "unstable" feature on zcash_client_sqlite
// and need further work to properly match the Haskell FFI signatures.
// TODO: Implement when discussing block scanning.

// ============================================================================
// Subtree Root Operations
// ============================================================================
// NOTE: These require proper CommitmentTreeRoot usage from zcash_client_backend.
// TODO: Implement when discussing block scanning.

// ============================================================================
// Transaction Proposals
// ============================================================================
// NOTE: These require careful API matching with zcash_client_backend.
// TODO: Implement when discussing transaction creation.

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_address::unified::{Address, Encoding};
    use zcash_address::ToAddress;

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
        assert!(is_valid_shielded_address(
            TEST_UNIFIED_ADDRESS,
            NetworkType::Main
        ));
    }

    #[test]
    fn test_valid_sapling_address_extracted_from_ua() {
        let sapling_addr = extract_sapling_address_from_ua(TEST_UNIFIED_ADDRESS)
            .expect("Test UA should contain a Sapling receiver");
        assert!(sapling_addr.starts_with("zs1"));
        assert!(is_valid_shielded_address(&sapling_addr, NetworkType::Main));
    }

    #[test]
    fn test_invalid_address() {
        assert!(!is_valid_shielded_address(
            "not_a_valid_address",
            NetworkType::Main
        ));
    }
}
