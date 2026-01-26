//! FFI type definitions for the lrzhs light client library.
//!
//! This module contains all `#[repr(C)]` structs and associated memory management
//! functions for safe interop with Haskell.

use std::ffi::c_char;
use std::ptr;

use zcash_client_sqlite::AccountUuid;

/// A UUID represented as 16 bytes for FFI.
#[repr(C)]
pub struct FfiUuid {
    pub bytes: [u8; 16],
}

impl FfiUuid {
    pub fn from_uuid(uuid: uuid::Uuid) -> Self {
        FfiUuid {
            bytes: *uuid.as_bytes(),
        }
    }

    pub fn from_account_uuid(account_uuid: AccountUuid) -> Self {
        Self::from_uuid(account_uuid.expose_uuid())
    }

    pub fn to_uuid(&self) -> uuid::Uuid {
        uuid::Uuid::from_bytes(self.bytes)
    }

    pub fn to_account_uuid(&self) -> AccountUuid {
        AccountUuid::from_uuid(self.to_uuid())
    }
}

/// Account information returned from account queries.
#[repr(C)]
pub struct FfiAccount {
    pub uuid: FfiUuid,
    pub name: *mut c_char,
    pub key_source: *mut c_char,
    /// The UFVK as an encoded string, or null if not available.
    pub ufvk: *mut c_char,
    /// The UIVK as an encoded string, or null if not available.
    pub uivk: *mut c_char,
    /// Whether the account has spend capability.
    pub has_spend_key: bool,
}

impl Drop for FfiAccount {
    fn drop(&mut self) {
        unsafe {
            if !self.name.is_null() {
                drop(std::ffi::CString::from_raw(self.name));
            }
            if !self.key_source.is_null() {
                drop(std::ffi::CString::from_raw(self.key_source));
            }
            if !self.ufvk.is_null() {
                drop(std::ffi::CString::from_raw(self.ufvk));
            }
            if !self.uivk.is_null() {
                drop(std::ffi::CString::from_raw(self.uivk));
            }
        }
    }
}

/// A list of accounts.
#[repr(C)]
pub struct FfiAccounts {
    pub accounts: *mut FfiUuid,
    pub len: usize,
}

impl Drop for FfiAccounts {
    fn drop(&mut self) {
        if !self.accounts.is_null() && self.len > 0 {
            unsafe {
                let _ = Vec::from_raw_parts(self.accounts, self.len, self.len);
            }
        }
    }
}

/// Balance information for a single pool.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FfiBalance {
    /// Spendable balance in zatoshis.
    pub spendable: i64,
    /// Change that is pending confirmation.
    pub change_pending: i64,
    /// Value pending from incoming transactions.
    pub value_pending: i64,
}

/// Balance information for a single account, broken down by pool.
#[repr(C)]
pub struct FfiAccountBalance {
    pub account_uuid: FfiUuid,
    pub sapling_balance: FfiBalance,
    pub orchard_balance: FfiBalance,
}

/// Wallet summary containing all account balances and sync progress.
#[repr(C)]
pub struct FfiWalletSummary {
    pub account_balances: *mut FfiAccountBalance,
    pub account_balances_len: usize,
    /// Chain tip height, or -1 if unknown.
    pub chain_tip_height: i64,
    /// Fully scanned height, or -1 if unknown.
    pub fully_scanned_height: i64,
    /// Scan progress numerator.
    pub scan_progress_numerator: u64,
    /// Scan progress denominator.
    pub scan_progress_denominator: u64,
    /// Next Sapling subtree index to fetch.
    pub next_sapling_subtree_index: u64,
    /// Next Orchard subtree index to fetch.
    pub next_orchard_subtree_index: u64,
}

impl Drop for FfiWalletSummary {
    fn drop(&mut self) {
        if !self.account_balances.is_null() && self.account_balances_len > 0 {
            unsafe {
                let _ = Vec::from_raw_parts(
                    self.account_balances,
                    self.account_balances_len,
                    self.account_balances_len,
                );
            }
        }
    }
}

/// Summary of a block scanning operation.
#[repr(C)]
pub struct FfiScanSummary {
    /// The start height of the scan range.
    pub scanned_start: i64,
    /// The end height of the scan range (exclusive).
    pub scanned_end: i64,
    /// Number of blocks scanned.
    pub scanned_count: u64,
    /// Number of notes received.
    pub received_notes: u64,
    /// Number of notes spent.
    pub spent_notes: u64,
}

/// Scan priority for a range.
#[repr(C)]
#[derive(Clone, Copy)]
pub enum FfiScanPriority {
    /// Block range has been verified and is no longer relevant.
    Scanned = 0,
    /// Block range is historical and can be scanned in the background.
    Historic = 1,
    /// Block range should be scanned at some point.
    OpenAdjacent = 2,
    /// Block range has not yet been verified.
    Verify = 3,
    /// Block range has been found to contain notes after a rewind.
    FoundNote = 4,
    /// Block range should be scanned ASAP for wallet recovery.
    ChainTip = 5,
}

/// A scan range with priority.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FfiScanRange {
    pub start: i64,
    pub end: i64,
    pub priority: FfiScanPriority,
}

/// A list of scan ranges.
#[repr(C)]
pub struct FfiScanRanges {
    pub ranges: *mut FfiScanRange,
    pub len: usize,
}

impl Drop for FfiScanRanges {
    fn drop(&mut self) {
        if !self.ranges.is_null() && self.len > 0 {
            unsafe {
                let _ = Vec::from_raw_parts(self.ranges, self.len, self.len);
            }
        }
    }
}

/// A boxed slice of bytes for returning binary data.
#[repr(C)]
pub struct FfiBoxedSlice {
    pub ptr: *mut u8,
    pub len: usize,
}

impl Drop for FfiBoxedSlice {
    fn drop(&mut self) {
        if !self.ptr.is_null() && self.len > 0 {
            unsafe {
                let _ = Vec::from_raw_parts(self.ptr, self.len, self.len);
            }
        }
    }
}

impl FfiBoxedSlice {
    pub fn from_vec(v: Vec<u8>) -> *mut Self {
        let len = v.len();
        let ptr = if len > 0 {
            let mut v = v;
            let ptr = v.as_mut_ptr();
            std::mem::forget(v);
            ptr
        } else {
            ptr::null_mut()
        };
        Box::into_raw(Box::new(FfiBoxedSlice { ptr, len }))
    }

    pub fn empty() -> *mut Self {
        Box::into_raw(Box::new(FfiBoxedSlice {
            ptr: ptr::null_mut(),
            len: 0,
        }))
    }
}

/// A binary key (USK or seed fingerprint).
#[repr(C)]
pub struct FfiBinaryKey {
    pub data: *mut u8,
    pub len: usize,
}

impl Drop for FfiBinaryKey {
    fn drop(&mut self) {
        if !self.data.is_null() && self.len > 0 {
            unsafe {
                let _ = Vec::from_raw_parts(self.data, self.len, self.len);
            }
        }
    }
}

impl FfiBinaryKey {
    pub fn from_vec(v: Vec<u8>) -> *mut Self {
        let len = v.len();
        let ptr = if len > 0 {
            let mut v = v;
            let ptr = v.as_mut_ptr();
            std::mem::forget(v);
            ptr
        } else {
            ptr::null_mut()
        };
        Box::into_raw(Box::new(FfiBinaryKey { data: ptr, len }))
    }
}

/// A list of transaction IDs.
#[repr(C)]
pub struct FfiTxIds {
    pub txids: *mut [u8; 32],
    pub len: usize,
}

impl Drop for FfiTxIds {
    fn drop(&mut self) {
        if !self.txids.is_null() && self.len > 0 {
            unsafe {
                let _ = Vec::from_raw_parts(self.txids, self.len, self.len);
            }
        }
    }
}

impl FfiTxIds {
    pub fn from_vec(v: Vec<[u8; 32]>) -> *mut Self {
        let len = v.len();
        let ptr = if len > 0 {
            let mut v = v;
            let ptr = v.as_mut_ptr();
            std::mem::forget(v);
            ptr
        } else {
            ptr::null_mut()
        };
        Box::into_raw(Box::new(FfiTxIds { txids: ptr, len }))
    }
}

/// Block metadata for writing to the block cache.
#[repr(C)]
pub struct FfiBlockMeta {
    pub height: u32,
    pub hash: [u8; 32],
    pub time: u32,
    pub sapling_outputs_count: u32,
    pub orchard_actions_count: u32,
}

/// A list of block metadata.
#[repr(C)]
pub struct FfiBlockMetaList {
    pub blocks: *const FfiBlockMeta,
    pub len: usize,
}

/// A subtree root for commitment tree updates.
#[repr(C)]
pub struct FfiSubtreeRoot {
    pub root_hash: [u8; 32],
    pub completing_block_height: u32,
}

/// A list of subtree roots.
#[repr(C)]
pub struct FfiSubtreeRoots {
    pub roots: *const FfiSubtreeRoot,
    pub len: usize,
}

/// Tree state for account birthday or recovery.
#[repr(C)]
pub struct FfiTreeState {
    pub height: u32,
    pub hash: [u8; 32],
    pub time: u32,
    /// Sapling tree frontier encoded bytes, or null if empty.
    pub sapling_tree: *const u8,
    pub sapling_tree_len: usize,
    /// Orchard tree frontier encoded bytes, or null if empty.
    pub orchard_tree: *const u8,
    pub orchard_tree_len: usize,
}

/// Result of creating an account: UUID and USK.
#[repr(C)]
pub struct FfiCreateAccountResult {
    pub uuid: FfiUuid,
    pub usk: *mut u8,
    pub usk_len: usize,
}

impl Drop for FfiCreateAccountResult {
    fn drop(&mut self) {
        if !self.usk.is_null() && self.usk_len > 0 {
            unsafe {
                // Zero out the USK before freeing
                std::ptr::write_bytes(self.usk, 0, self.usk_len);
                let _ = Vec::from_raw_parts(self.usk, self.usk_len, self.usk_len);
            }
        }
    }
}

// Free functions for FFI types

/// Free a UUID pointer allocated by this library.
///
/// # Safety
/// The pointer must have been allocated by this library.
#[no_mangle]
pub unsafe extern "C" fn lrzhs_free_uuid(ptr: *mut FfiUuid) {
    if !ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(ptr);
        }
    }
}

/// Free an account pointer allocated by this library.
///
/// # Safety
/// The pointer must have been allocated by this library.
#[no_mangle]
pub unsafe extern "C" fn lrzhs_free_account(ptr: *mut FfiAccount) {
    if !ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(ptr);
        }
    }
}

/// Free an accounts list pointer allocated by this library.
///
/// # Safety
/// The pointer must have been allocated by this library.
#[no_mangle]
pub unsafe extern "C" fn lrzhs_free_accounts(ptr: *mut FfiAccounts) {
    if !ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(ptr);
        }
    }
}

/// Free a wallet summary pointer allocated by this library.
///
/// # Safety
/// The pointer must have been allocated by this library.
#[no_mangle]
pub unsafe extern "C" fn lrzhs_free_wallet_summary(ptr: *mut FfiWalletSummary) {
    if !ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(ptr);
        }
    }
}

/// Free a scan summary pointer allocated by this library.
///
/// # Safety
/// The pointer must have been allocated by this library.
#[no_mangle]
pub unsafe extern "C" fn lrzhs_free_scan_summary(ptr: *mut FfiScanSummary) {
    if !ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(ptr);
        }
    }
}

/// Free a scan ranges pointer allocated by this library.
///
/// # Safety
/// The pointer must have been allocated by this library.
#[no_mangle]
pub unsafe extern "C" fn lrzhs_free_scan_ranges(ptr: *mut FfiScanRanges) {
    if !ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(ptr);
        }
    }
}

/// Free a boxed slice pointer allocated by this library.
///
/// # Safety
/// The pointer must have been allocated by this library.
#[no_mangle]
pub unsafe extern "C" fn lrzhs_free_boxed_slice(ptr: *mut FfiBoxedSlice) {
    if !ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(ptr);
        }
    }
}

/// Free a binary key pointer allocated by this library.
///
/// # Safety
/// The pointer must have been allocated by this library.
#[no_mangle]
pub unsafe extern "C" fn lrzhs_free_binary_key(ptr: *mut FfiBinaryKey) {
    if !ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(ptr);
        }
    }
}

/// Free a transaction IDs pointer allocated by this library.
///
/// # Safety
/// The pointer must have been allocated by this library.
#[no_mangle]
pub unsafe extern "C" fn lrzhs_free_txids(ptr: *mut FfiTxIds) {
    if !ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(ptr);
        }
    }
}

/// Free a create account result pointer allocated by this library.
///
/// # Safety
/// The pointer must have been allocated by this library.
#[no_mangle]
pub unsafe extern "C" fn lrzhs_free_create_account_result(ptr: *mut FfiCreateAccountResult) {
    if !ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(ptr);
        }
    }
}

/// Free a string allocated by this library.
///
/// # Safety
/// The pointer must have been allocated by this library as a CString.
#[no_mangle]
pub unsafe extern "C" fn lrzhs_string_free(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = std::ffi::CString::from_raw(s);
        }
    }
}
