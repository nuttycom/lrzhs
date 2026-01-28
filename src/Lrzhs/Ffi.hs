{-# LANGUAGE ForeignFunctionInterface #-}

module Lrzhs.Ffi
  ( -- * Network Conversion
    networkId
  , poolId

    -- * Error Handling
  , getLastError
  , clearLastError

    -- * Initialization
  , rs_init_on_load
  , rs_init_data_database
  , rs_init_block_metadata_db

    -- * Wallet Handle Management
  , rs_open_wallet
  , rs_close_wallet
  , DbHandle

    -- * Account Management
  , rs_create_account
  , rs_import_account_ufvk
  , rs_list_accounts
  , rs_get_account
  , rs_seed_fingerprint

    -- * Address Generation
  , rs_get_current_address
  , rs_get_next_available_address

    -- * Wallet Summary
  , rs_get_wallet_summary

    -- * Blockchain Synchronization
  , rs_update_chain_tip
  , rs_fully_scanned_height
  , rs_suggest_scan_ranges
  , rs_write_block_metadata
  , rs_latest_cached_block_height
  , rs_rewind_fs_block_cache_to_height
  , rs_put_sapling_subtree_roots
  , rs_put_orchard_subtree_roots

    -- * Transaction Proposals
  , rs_propose_transfer
  , rs_propose_transfer_from_uri

    -- * Transaction Creation
  , rs_create_proposed_transactions

    -- * Transaction Data & Memos
  , rs_get_memo
  , rs_decrypt_and_store_transaction

    -- * Utilities
  , rs_branch_id_for_height
  , rs_is_valid_shielded_address

    -- * Memory Management
  , rs_string_free
  , rs_free_uuid
  , rs_free_account
  , rs_free_accounts
  , rs_free_wallet_summary
  , rs_free_scan_ranges
  , rs_free_boxed_slice
  , rs_free_binary_key
  , rs_free_txids
  , rs_free_create_account_result

    -- * FFI Types
  , FfiUuid (..)
  , FfiAccount (..)
  , FfiAccounts (..)
  , FfiBalance (..)
  , FfiAccountBalance (..)
  , FfiWalletSummary (..)
  , FfiScanRange (..)
  , FfiScanRanges (..)
  , FfiBoxedSlice (..)
  , FfiBinaryKey (..)
  , FfiTxIds (..)
  , FfiBlockMeta (..)
  , FfiSubtreeRoot (..)
  , FfiCreateAccountResult (..)
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Unsafe as BSU
import Data.Int (Int32, Int64)
import Data.Text (Text, pack, unpack)
import Data.Word (Word8, Word16, Word32, Word64)
import Foreign.C (CBool (..), CChar, CInt (..), CUInt (..), CSize (..))
import Foreign.C.String (CString, peekCString, withCString)
import Foreign.Marshal.Alloc (allocaBytes, mallocBytes, free)
import Foreign.Marshal.Array (peekArray, allocaArray)
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr (Ptr, nullPtr, castPtr, plusPtr)
import Foreign.Storable (Storable (..), peek, poke)
import Lrzhs.Types

-- | Convert Network to FFI network ID.
networkId :: Network -> CUInt
networkId = \case
  Mainnet -> 1
  Testnet -> 0

-- | Convert Pool to FFI pool ID.
poolId :: Pool -> Word8
poolId = \case
  Sapling -> 2
  Orchard -> 3

-- ============================================================================
-- FFI Storable Types
-- ============================================================================

-- | FFI UUID (16 bytes).
newtype FfiUuid = FfiUuid { ffiUuidBytes :: ByteString }

instance Storable FfiUuid where
  sizeOf _ = 16
  alignment _ = 1
  peek ptr = do
    bytes <- BS.packCStringLen (castPtr ptr, 16)
    return $ FfiUuid bytes
  poke ptr (FfiUuid bs) = BSU.unsafeUseAsCStringLen bs $ \(src, _) ->
    copyBytes (castPtr ptr) (castPtr src) 16

-- | FFI Account structure.
data FfiAccount = FfiAccount
  { ffiAccountUuid :: !FfiUuid
  , ffiAccountName :: !(Ptr CChar)
  , ffiAccountKeySource :: !(Ptr CChar)
  , ffiAccountUfvk :: !(Ptr CChar)
  , ffiAccountUivk :: !(Ptr CChar)
  , ffiAccountHasSpendKey :: !CBool
  }

instance Storable FfiAccount where
  sizeOf _ = 16 + 5 * sizeOf (undefined :: Ptr ()) + sizeOf (undefined :: CBool)
  alignment _ = alignment (undefined :: Ptr ())
  peek ptr = do
    uuid <- peek (castPtr ptr)
    let ptrBase = castPtr ptr `plusPtr` 16
    name <- peekElemOff (castPtr ptrBase) 0
    keySource <- peekElemOff (castPtr ptrBase) 1
    ufvk <- peekElemOff (castPtr ptrBase) 2
    uivk <- peekElemOff (castPtr ptrBase) 3
    hasSpend <- peekElemOff (castPtr ptrBase `plusPtr` (4 * sizeOf (undefined :: Ptr ()))) 0
    return $ FfiAccount uuid name keySource ufvk uivk hasSpend
  poke = error "poke not implemented for FfiAccount"

-- | FFI Accounts list.
data FfiAccounts = FfiAccounts
  { ffiAccountsPtr :: !(Ptr FfiUuid)
  , ffiAccountsLen :: !CSize
  }

instance Storable FfiAccounts where
  sizeOf _ = sizeOf (undefined :: Ptr ()) + sizeOf (undefined :: CSize)
  alignment _ = alignment (undefined :: Ptr ())
  peek ptr = do
    p <- peek (castPtr ptr)
    len <- peekByteOff ptr (sizeOf (undefined :: Ptr ()))
    return $ FfiAccounts p len
  poke = error "poke not implemented for FfiAccounts"

-- | FFI Balance structure.
data FfiBalance = FfiBalance
  { ffiBalanceSpendable :: !Int64
  , ffiBalanceChangePending :: !Int64
  , ffiBalanceValuePending :: !Int64
  }

instance Storable FfiBalance where
  sizeOf _ = 3 * sizeOf (undefined :: Int64)
  alignment _ = alignment (undefined :: Int64)
  peek ptr = do
    spendable <- peekByteOff ptr 0
    changePending <- peekByteOff ptr 8
    valuePending <- peekByteOff ptr 16
    return $ FfiBalance spendable changePending valuePending
  poke ptr (FfiBalance s c v) = do
    pokeByteOff ptr 0 s
    pokeByteOff ptr 8 c
    pokeByteOff ptr 16 v

-- | FFI Account Balance structure.
data FfiAccountBalance = FfiAccountBalance
  { ffiAccountBalanceUuid :: !FfiUuid
  , ffiAccountBalanceSapling :: !FfiBalance
  , ffiAccountBalanceOrchard :: !FfiBalance
  }

instance Storable FfiAccountBalance where
  sizeOf _ = 16 + 2 * sizeOf (undefined :: FfiBalance)
  alignment _ = alignment (undefined :: Int64)
  peek ptr = do
    uuid <- peek (castPtr ptr)
    sapling <- peekByteOff ptr 16
    orchard <- peekByteOff ptr (16 + sizeOf (undefined :: FfiBalance))
    return $ FfiAccountBalance uuid sapling orchard
  poke = error "poke not implemented for FfiAccountBalance"

-- | FFI Wallet Summary structure.
data FfiWalletSummary = FfiWalletSummary
  { ffiWalletSummaryBalances :: !(Ptr FfiAccountBalance)
  , ffiWalletSummaryBalancesLen :: !CSize
  , ffiWalletSummaryChainTip :: !Int64
  , ffiWalletSummaryFullyScanned :: !Int64
  , ffiWalletSummaryScanNumerator :: !Word64
  , ffiWalletSummaryScanDenominator :: !Word64
  , ffiWalletSummaryNextSapling :: !Word64
  , ffiWalletSummaryNextOrchard :: !Word64
  }

instance Storable FfiWalletSummary where
  sizeOf _ = sizeOf (undefined :: Ptr ()) + sizeOf (undefined :: CSize) + 6 * sizeOf (undefined :: Int64)
  alignment _ = alignment (undefined :: Ptr ())
  peek ptr = do
    balPtr <- peek (castPtr ptr)
    let offset1 = sizeOf (undefined :: Ptr ())
    balLen <- peekByteOff ptr offset1
    let offset2 = offset1 + sizeOf (undefined :: CSize)
    chainTip <- peekByteOff ptr offset2
    fullyScanned <- peekByteOff ptr (offset2 + 8)
    scanNum <- peekByteOff ptr (offset2 + 16)
    scanDen <- peekByteOff ptr (offset2 + 24)
    nextSap <- peekByteOff ptr (offset2 + 32)
    nextOrch <- peekByteOff ptr (offset2 + 40)
    return $ FfiWalletSummary balPtr balLen chainTip fullyScanned scanNum scanDen nextSap nextOrch
  poke = error "poke not implemented for FfiWalletSummary"

-- | FFI Scan Range structure.
data FfiScanRange = FfiScanRange
  { ffiScanRangeStart :: !Int64
  , ffiScanRangeEnd :: !Int64
  , ffiScanRangePriority :: !CInt
  }

instance Storable FfiScanRange where
  sizeOf _ = 2 * sizeOf (undefined :: Int64) + sizeOf (undefined :: CInt)
  alignment _ = alignment (undefined :: Int64)
  peek ptr = do
    start <- peekByteOff ptr 0
    end <- peekByteOff ptr 8
    priority <- peekByteOff ptr 16
    return $ FfiScanRange start end priority
  poke ptr (FfiScanRange s e p) = do
    pokeByteOff ptr 0 s
    pokeByteOff ptr 8 e
    pokeByteOff ptr 16 p

-- | FFI Scan Ranges list.
data FfiScanRanges = FfiScanRanges
  { ffiScanRangesPtr :: !(Ptr FfiScanRange)
  , ffiScanRangesLen :: !CSize
  }

instance Storable FfiScanRanges where
  sizeOf _ = sizeOf (undefined :: Ptr ()) + sizeOf (undefined :: CSize)
  alignment _ = alignment (undefined :: Ptr ())
  peek ptr = do
    p <- peek (castPtr ptr)
    len <- peekByteOff ptr (sizeOf (undefined :: Ptr ()))
    return $ FfiScanRanges p len
  poke = error "poke not implemented for FfiScanRanges"

-- | FFI Boxed Slice for binary data.
data FfiBoxedSlice = FfiBoxedSlice
  { ffiBoxedSlicePtr :: !(Ptr Word8)
  , ffiBoxedSliceLen :: !CSize
  }

instance Storable FfiBoxedSlice where
  sizeOf _ = sizeOf (undefined :: Ptr ()) + sizeOf (undefined :: CSize)
  alignment _ = alignment (undefined :: Ptr ())
  peek ptr = do
    p <- peek (castPtr ptr)
    len <- peekByteOff ptr (sizeOf (undefined :: Ptr ()))
    return $ FfiBoxedSlice p len
  poke = error "poke not implemented for FfiBoxedSlice"

-- | FFI Binary Key.
data FfiBinaryKey = FfiBinaryKey
  { ffiBinaryKeyPtr :: !(Ptr Word8)
  , ffiBinaryKeyLen :: !CSize
  }

instance Storable FfiBinaryKey where
  sizeOf _ = sizeOf (undefined :: Ptr ()) + sizeOf (undefined :: CSize)
  alignment _ = alignment (undefined :: Ptr ())
  peek ptr = do
    p <- peek (castPtr ptr)
    len <- peekByteOff ptr (sizeOf (undefined :: Ptr ()))
    return $ FfiBinaryKey p len
  poke = error "poke not implemented for FfiBinaryKey"

-- | FFI Transaction IDs list.
data FfiTxIds = FfiTxIds
  { ffiTxIdsPtr :: !(Ptr Word8)  -- Pointer to array of [u8; 32]
  , ffiTxIdsLen :: !CSize
  }

instance Storable FfiTxIds where
  sizeOf _ = sizeOf (undefined :: Ptr ()) + sizeOf (undefined :: CSize)
  alignment _ = alignment (undefined :: Ptr ())
  peek ptr = do
    p <- peek (castPtr ptr)
    len <- peekByteOff ptr (sizeOf (undefined :: Ptr ()))
    return $ FfiTxIds p len
  poke = error "poke not implemented for FfiTxIds"

-- | FFI Block Metadata.
data FfiBlockMeta = FfiBlockMeta
  { ffiBlockMetaHeight :: !Word32
  , ffiBlockMetaHash :: !ByteString  -- 32 bytes
  , ffiBlockMetaTime :: !Word32
  , ffiBlockMetaSaplingOutputs :: !Word32
  , ffiBlockMetaOrchardActions :: !Word32
  }

instance Storable FfiBlockMeta where
  sizeOf _ = 4 + 32 + 4 + 4 + 4
  alignment _ = alignment (undefined :: Word32)
  peek ptr = do
    h <- peekByteOff ptr 0
    hash <- BS.packCStringLen (castPtr (ptr `plusPtr` 4), 32)
    t <- peekByteOff ptr 36
    sap <- peekByteOff ptr 40
    orch <- peekByteOff ptr 44
    return $ FfiBlockMeta h hash t sap orch
  poke ptr (FfiBlockMeta h hash t sap orch) = do
    pokeByteOff ptr 0 h
    BSU.unsafeUseAsCStringLen hash $ \(src, _) ->
      copyBytes (castPtr (ptr `plusPtr` 4)) (castPtr src) 32
    pokeByteOff ptr 36 t
    pokeByteOff ptr 40 sap
    pokeByteOff ptr 44 orch

-- | FFI Subtree Root.
data FfiSubtreeRoot = FfiSubtreeRoot
  { ffiSubtreeRootHash :: !ByteString  -- 32 bytes
  , ffiSubtreeRootHeight :: !Word32
  }

instance Storable FfiSubtreeRoot where
  sizeOf _ = 32 + 4
  alignment _ = alignment (undefined :: Word32)
  peek ptr = do
    hash <- BS.packCStringLen (castPtr ptr, 32)
    h <- peekByteOff ptr 32
    return $ FfiSubtreeRoot hash h
  poke ptr (FfiSubtreeRoot hash h) = do
    BSU.unsafeUseAsCStringLen hash $ \(src, _) ->
      copyBytes (castPtr ptr) (castPtr src) 32
    pokeByteOff ptr 32 h

-- | FFI Create Account Result.
data FfiCreateAccountResult = FfiCreateAccountResult
  { ffiCreateAccountUuid :: !FfiUuid
  , ffiCreateAccountUsk :: !(Ptr Word8)
  , ffiCreateAccountUskLen :: !CSize
  }

instance Storable FfiCreateAccountResult where
  sizeOf _ = 16 + sizeOf (undefined :: Ptr ()) + sizeOf (undefined :: CSize)
  alignment _ = alignment (undefined :: Ptr ())
  peek ptr = do
    uuid <- peek (castPtr ptr)
    usk <- peekByteOff ptr 16
    uskLen <- peekByteOff ptr (16 + sizeOf (undefined :: Ptr ()))
    return $ FfiCreateAccountResult uuid usk uskLen
  poke = error "poke not implemented for FfiCreateAccountResult"

-- ============================================================================
-- Error Handling
-- ============================================================================

foreign import ccall "lrzhs_last_error_length" rs_last_error_length :: IO Int32
foreign import ccall "lrzhs_error_message_utf8" rs_error_message_utf8 :: Ptr CChar -> Int32 -> IO Int32
foreign import ccall "lrzhs_clear_last_error" rs_clear_last_error :: IO ()

-- | Get the last error message from the FFI layer.
getLastError :: IO (Maybe Text)
getLastError = do
  len <- rs_last_error_length
  if len <= 0
    then return Nothing
    else allocaBytes (fromIntegral len) $ \buf -> do
      _ <- rs_error_message_utf8 buf len
      str <- peekCString buf
      return $ Just (pack str)

-- | Clear the last error.
clearLastError :: IO ()
clearLastError = rs_clear_last_error

-- ============================================================================
-- Initialization
-- ============================================================================

foreign import ccall "lrzhs_init_on_load" rs_init_on_load :: Word8 -> IO ()

foreign import ccall "lrzhs_init_data_database"
  rs_init_data_database :: Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> CUInt -> IO Int32

foreign import ccall "lrzhs_init_block_metadata_db"
  rs_init_block_metadata_db :: Ptr Word8 -> CSize -> IO CBool

-- ============================================================================
-- Wallet Handle Management
-- ============================================================================

-- | Opaque handle to an open wallet database connection.
data DbHandle

foreign import ccall "lrzhs_open_wallet"
  rs_open_wallet :: Ptr Word8 -> CSize -> CUInt -> IO (Ptr DbHandle)

foreign import ccall "lrzhs_close_wallet"
  rs_close_wallet :: Ptr DbHandle -> IO ()

-- ============================================================================
-- Account Management
-- ============================================================================

foreign import ccall "lrzhs_create_account"
  rs_create_account
    :: Ptr DbHandle              -- handle
    -> Ptr Word8 -> CSize        -- seed
    -> Word32                    -- treestate_height
    -> Ptr Word8                 -- treestate_hash
    -> Word32                    -- treestate_time
    -> Ptr Word8 -> CSize        -- treestate_sapling_tree
    -> Ptr Word8 -> CSize        -- treestate_orchard_tree
    -> Int64                     -- recover_until
    -> CString                   -- account_name
    -> CString                   -- key_source
    -> IO (Ptr FfiCreateAccountResult)

foreign import ccall "lrzhs_import_account_ufvk"
  rs_import_account_ufvk
    :: Ptr DbHandle              -- handle
    -> CString                   -- ufvk
    -> Word32                    -- treestate_height
    -> Ptr Word8                 -- treestate_hash
    -> Word32                    -- treestate_time
    -> Ptr Word8 -> CSize        -- treestate_sapling_tree
    -> Ptr Word8 -> CSize        -- treestate_orchard_tree
    -> Int64                     -- recover_until
    -> CBool                     -- spending
    -> CString                   -- account_name
    -> CString                   -- key_source
    -> Ptr Word8                 -- seed_fingerprint
    -> Word32                    -- hd_account_index
    -> IO (Ptr FfiUuid)

foreign import ccall "lrzhs_list_accounts"
  rs_list_accounts :: Ptr DbHandle -> IO (Ptr FfiAccounts)

foreign import ccall "lrzhs_get_account"
  rs_get_account :: Ptr DbHandle -> Ptr Word8 -> IO (Ptr FfiAccount)

foreign import ccall "lrzhs_seed_fingerprint"
  rs_seed_fingerprint :: Ptr Word8 -> CSize -> Ptr Word8 -> IO CBool

-- ============================================================================
-- Address Generation
-- ============================================================================

foreign import ccall "lrzhs_get_current_address"
  rs_get_current_address :: Ptr DbHandle -> Ptr Word8 -> IO CString

foreign import ccall "lrzhs_get_next_available_address"
  rs_get_next_available_address :: Ptr DbHandle -> Ptr Word8 -> Word8 -> IO CString

-- ============================================================================
-- Wallet Summary
-- ============================================================================

foreign import ccall "lrzhs_get_wallet_summary"
  rs_get_wallet_summary :: Ptr DbHandle -> Word32 -> IO (Ptr FfiWalletSummary)

-- ============================================================================
-- Blockchain Synchronization
-- ============================================================================

foreign import ccall "lrzhs_update_chain_tip"
  rs_update_chain_tip :: Ptr DbHandle -> Word32 -> IO CBool

foreign import ccall "lrzhs_fully_scanned_height"
  rs_fully_scanned_height :: Ptr DbHandle -> IO Int64

foreign import ccall "lrzhs_suggest_scan_ranges"
  rs_suggest_scan_ranges :: Ptr DbHandle -> IO (Ptr FfiScanRanges)

foreign import ccall "lrzhs_write_block_metadata"
  rs_write_block_metadata :: Ptr Word8 -> CSize -> Ptr FfiBlockMeta -> CSize -> IO CBool

foreign import ccall "lrzhs_latest_cached_block_height"
  rs_latest_cached_block_height :: Ptr Word8 -> CSize -> IO Int64

foreign import ccall "lrzhs_rewind_fs_block_cache_to_height"
  rs_rewind_fs_block_cache_to_height :: Ptr Word8 -> CSize -> Word32 -> IO CBool

foreign import ccall "lrzhs_put_sapling_subtree_roots"
  rs_put_sapling_subtree_roots :: Ptr Word8 -> CSize -> Word64 -> Ptr FfiSubtreeRoot -> CSize -> CUInt -> IO CBool

foreign import ccall "lrzhs_put_orchard_subtree_roots"
  rs_put_orchard_subtree_roots :: Ptr Word8 -> CSize -> Word64 -> Ptr FfiSubtreeRoot -> CSize -> CUInt -> IO CBool

-- ============================================================================
-- Transaction Proposals
-- ============================================================================

foreign import ccall "lrzhs_propose_transfer"
  rs_propose_transfer
    :: Ptr Word8 -> CSize        -- db_data
    -> Ptr Word8                 -- account_uuid
    -> CString                   -- to_address
    -> Int64                     -- value
    -> Ptr Word8 -> CSize        -- memo
    -> CUInt                     -- network_id
    -> Word32                    -- min_confirmations
    -> IO (Ptr FfiBoxedSlice)

foreign import ccall "lrzhs_propose_transfer_from_uri"
  rs_propose_transfer_from_uri
    :: Ptr Word8 -> CSize        -- db_data
    -> Ptr Word8                 -- account_uuid
    -> CString                   -- payment_uri
    -> CUInt                     -- network_id
    -> Word32                    -- min_confirmations
    -> IO (Ptr FfiBoxedSlice)

-- ============================================================================
-- Transaction Creation
-- ============================================================================

foreign import ccall "lrzhs_create_proposed_transactions"
  rs_create_proposed_transactions
    :: Ptr Word8 -> CSize        -- db_data
    -> Ptr Word8 -> CSize        -- proposal
    -> Ptr Word8 -> CSize        -- usk
    -> CUInt                     -- network_id
    -> IO (Ptr FfiTxIds)

-- ============================================================================
-- Transaction Data & Memos
-- ============================================================================

foreign import ccall "lrzhs_get_memo"
  rs_get_memo
    :: Ptr Word8 -> CSize        -- db_data
    -> Ptr Word8                 -- txid
    -> Word8                     -- pool
    -> Word16                    -- output_index
    -> Ptr Word8                 -- memo_out
    -> CUInt                     -- network_id
    -> IO CBool

foreign import ccall "lrzhs_decrypt_and_store_transaction"
  rs_decrypt_and_store_transaction
    :: Ptr Word8 -> CSize        -- db_data
    -> Ptr Word8 -> CSize        -- tx_bytes
    -> Int64                     -- mined_height
    -> CUInt                     -- network_id
    -> Ptr Word8                 -- txid_out
    -> IO Int32

-- ============================================================================
-- Utilities
-- ============================================================================

foreign import ccall "lrzhs_branch_id_for_height"
  rs_branch_id_for_height :: Word32 -> CUInt -> IO Word32

foreign import ccall "lrzhs_is_valid_shielded_address"
  rs_is_valid_shielded_address :: CString -> CUInt -> IO CBool

-- ============================================================================
-- Memory Management
-- ============================================================================

foreign import ccall "lrzhs_string_free" rs_string_free :: CString -> IO ()
foreign import ccall "lrzhs_free_uuid" rs_free_uuid :: Ptr FfiUuid -> IO ()
foreign import ccall "lrzhs_free_account" rs_free_account :: Ptr FfiAccount -> IO ()
foreign import ccall "lrzhs_free_accounts" rs_free_accounts :: Ptr FfiAccounts -> IO ()
foreign import ccall "lrzhs_free_wallet_summary" rs_free_wallet_summary :: Ptr FfiWalletSummary -> IO ()
foreign import ccall "lrzhs_free_scan_ranges" rs_free_scan_ranges :: Ptr FfiScanRanges -> IO ()
foreign import ccall "lrzhs_free_boxed_slice" rs_free_boxed_slice :: Ptr FfiBoxedSlice -> IO ()
foreign import ccall "lrzhs_free_binary_key" rs_free_binary_key :: Ptr FfiBinaryKey -> IO ()
foreign import ccall "lrzhs_free_txids" rs_free_txids :: Ptr FfiTxIds -> IO ()
foreign import ccall "lrzhs_free_create_account_result" rs_free_create_account_result :: Ptr FfiCreateAccountResult -> IO ()
