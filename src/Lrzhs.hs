{-# LANGUAGE ScopedTypeVariables #-}

-- | Haskell light client library for Zcash.
--
-- This module provides a high-level API for interacting with the Zcash
-- blockchain using the zcash_client_backend and zcash_client_sqlite
-- libraries via FFI.
--
-- == Usage
--
-- @
-- import Lrzhs
-- import Lrzhs.Types
--
-- main :: IO ()
-- main = do
--   -- Initialize the library
--   initOnLoad LogInfo
--
--   -- Initialize the wallet database
--   result <- initDataDatabase "wallet.db" Nothing Testnet
--   case result of
--     Left err -> putStrLn $ "Error: " <> show err
--     Right _ -> putStrLn "Database initialized"
-- @
module Lrzhs
  ( -- * Initialization
    LogLevel (..)
  , initOnLoad
  , InitResult (..)
  , initDataDatabase
  , initBlockMetadataDb

    -- * Account Management
  , createAccount
  , importAccountUfvk
  , listAccounts
  , getAccount
  , seedFingerprint

    -- * Address Generation
  , getCurrentAddress
  , getNextAvailableAddress

    -- * Address Validation
  , isValidShieldedAddress

    -- * Wallet Summary
  , getWalletSummary

    -- * Blockchain Synchronization
  , updateChainTip
  , fullyScannedHeight
  , suggestScanRanges
  , writeBlockMetadata
  , latestCachedBlockHeight
  , rewindBlockCache
  , putSaplingSubtreeRoots
  , putOrchardSubtreeRoots

    -- * Transaction Proposals
  , proposeTransfer
  , proposeTransferFromUri

    -- * Transaction Creation
  , createProposedTransactions

    -- * Transaction Data & Memos
  , getMemo
  , decryptAndStoreTransaction

    -- * Utilities
  , branchIdForHeight
  , getLastError
  , clearLastError

    -- * Re-exports
  , module Lrzhs.Types
  ) where

import Control.Exception (bracket)
import Control.Monad (forM, when)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Unsafe as BSU
import Data.Int (Int32, Int64)
import Data.Text (Text, pack, unpack)
import qualified Data.Text.Encoding as TE
import Data.Word (Word8, Word16, Word32, Word64)
import Foreign.C (CBool (..), CSize (..), CUInt (..))
import Foreign.C.String (CString, peekCString, withCString)
import Foreign.Marshal.Alloc (allocaBytes, alloca)
import Foreign.Marshal.Array (withArray, peekArray, allocaArray)
import Foreign.Ptr (Ptr, nullPtr, castPtr, plusPtr)
import Foreign.Storable (peek, sizeOf, poke, peekByteOff)

import Lrzhs.Ffi
import Lrzhs.Types

-- ============================================================================
-- Initialization
-- ============================================================================

-- | Log level for the library.
data LogLevel
  = LogOff
  | LogError
  | LogWarn
  | LogInfo
  | LogDebug
  | LogTrace
  deriving (Eq, Ord, Show)

logLevelToWord8 :: LogLevel -> Word8
logLevelToWord8 = \case
  LogOff -> 0
  LogError -> 1
  LogWarn -> 2
  LogInfo -> 3
  LogDebug -> 4
  LogTrace -> 5

-- | Initialize the library with the specified log level.
-- This function is idempotent.
initOnLoad :: LogLevel -> IO ()
initOnLoad = rs_init_on_load . logLevelToWord8

-- | Result of database initialization.
data InitResult
  = InitCreated      -- ^ Database was created
  | InitExists       -- ^ Database already exists
  | InitNeedsSeed    -- ^ Database exists but needs seed for migration
  deriving (Eq, Show)

-- | Initialize the wallet data database.
-- Returns the initialization result or an error message.
initDataDatabase
  :: FilePath
  -> Maybe ByteString  -- ^ Optional seed for wallet recovery
  -> Network
  -> IO (Either Text InitResult)
initDataDatabase dbPath mSeed network = do
  let pathBS = TE.encodeUtf8 (pack dbPath)
  BSU.unsafeUseAsCStringLen pathBS $ \(pathPtr, pathLen) -> do
    case mSeed of
      Nothing -> do
        result <- rs_init_data_database
          (castPtr pathPtr) (fromIntegral pathLen)
          nullPtr 0
          (networkId network)
        handleInitResult result
      Just seed -> do
        BSU.unsafeUseAsCStringLen seed $ \(seedPtr, seedLen) -> do
          result <- rs_init_data_database
            (castPtr pathPtr) (fromIntegral pathLen)
            (castPtr seedPtr) (fromIntegral seedLen)
            (networkId network)
          handleInitResult result
  where
    handleInitResult result
      | result == 0 = return $ Right InitCreated
      | result == 1 = return $ Right InitExists
      | result == 3 = return $ Right InitNeedsSeed
      | otherwise = do
          err <- getLastError
          return $ Left $ maybe "Unknown error" id err

-- | Initialize the block metadata database (FsBlockDb).
initBlockMetadataDb :: FilePath -> IO (Either Text ())
initBlockMetadataDb dbPath = do
  let pathBS = TE.encodeUtf8 (pack dbPath)
  BSU.unsafeUseAsCStringLen pathBS $ \(pathPtr, pathLen) -> do
    CBool result <- rs_init_block_metadata_db (castPtr pathPtr) (fromIntegral pathLen)
    if result /= 0
      then return $ Right ()
      else do
        err <- getLastError
        return $ Left $ maybe "Unknown error" id err

-- ============================================================================
-- Account Management
-- ============================================================================

-- | Create a new account from a seed.
-- Returns the account ID and the unified spending key (USK).
createAccount
  :: FilePath
  -> ByteString       -- ^ Seed
  -> TreeState        -- ^ Birthday tree state
  -> Maybe BlockHeight -- ^ Recover until height
  -> Network
  -> Text             -- ^ Account name
  -> Maybe Text       -- ^ Key source
  -> IO (Either Text (AccountId, ByteString))
createAccount dbPath seed treeState recoverUntil network name keySource = do
  let pathBS = TE.encodeUtf8 (pack dbPath)
  BSU.unsafeUseAsCStringLen pathBS $ \(pathPtr, pathLen) ->
    BSU.unsafeUseAsCStringLen seed $ \(seedPtr, seedLen) ->
      BSU.unsafeUseAsCStringLen (unBlockHash $ treeStateHash treeState) $ \(hashPtr, _) ->
        withMaybeBS (treeStateSaplingTree treeState) $ \sapPtr sapLen ->
          withMaybeBS (treeStateOrchardTree treeState) $ \orchPtr orchLen ->
            withCString (unpack name) $ \namePtr ->
              withMaybeCString keySource $ \keySourcePtr -> do
                let recoverHeight = maybe (-1) (fromIntegral . unBlockHeight) recoverUntil
                resultPtr <- rs_create_account
                  (castPtr pathPtr) (fromIntegral pathLen)
                  (castPtr seedPtr) (fromIntegral seedLen)
                  (unBlockHeight $ treeStateHeight treeState)
                  (castPtr hashPtr)
                  (treeStateTime treeState)
                  sapPtr sapLen
                  orchPtr orchLen
                  recoverHeight
                  (networkId network)
                  namePtr
                  keySourcePtr
                if resultPtr == nullPtr
                  then do
                    err <- getLastError
                    return $ Left $ maybe "Unknown error" id err
                  else do
                    result <- peek resultPtr
                    let uuid = AccountId $ ffiUuidBytes $ ffiCreateAccountUuid result
                    uskLen <- return $ fromIntegral $ ffiCreateAccountUskLen result
                    usk <- BS.packCStringLen (castPtr $ ffiCreateAccountUsk result, uskLen)
                    rs_free_create_account_result resultPtr
                    return $ Right (uuid, usk)

-- | Import an account from a UFVK (view-only account).
importAccountUfvk
  :: FilePath
  -> Text             -- ^ UFVK encoded string
  -> TreeState        -- ^ Birthday tree state
  -> Maybe BlockHeight -- ^ Recover until height
  -> Network
  -> AccountPurpose
  -> Text             -- ^ Account name
  -> Maybe Text       -- ^ Key source
  -> IO (Either Text AccountId)
importAccountUfvk dbPath ufvk treeState recoverUntil network purpose name keySource = do
  let pathBS = TE.encodeUtf8 (pack dbPath)
  BSU.unsafeUseAsCStringLen pathBS $ \(pathPtr, pathLen) ->
    withCString (unpack ufvk) $ \ufvkPtr ->
      BSU.unsafeUseAsCStringLen (unBlockHash $ treeStateHash treeState) $ \(hashPtr, _) ->
        withMaybeBS (treeStateSaplingTree treeState) $ \sapPtr sapLen ->
          withMaybeBS (treeStateOrchardTree treeState) $ \orchPtr orchLen ->
            withCString (unpack name) $ \namePtr ->
              withMaybeCString keySource $ \keySourcePtr -> do
                let recoverHeight = maybe (-1) (fromIntegral . unBlockHeight) recoverUntil
                let spending = CBool $ case purpose of
                      Spending -> 1
                      ViewOnly -> 0
                resultPtr <- rs_import_account_ufvk
                  (castPtr pathPtr) (fromIntegral pathLen)
                  ufvkPtr
                  (unBlockHeight $ treeStateHeight treeState)
                  (castPtr hashPtr)
                  (treeStateTime treeState)
                  sapPtr sapLen
                  orchPtr orchLen
                  recoverHeight
                  (networkId network)
                  spending
                  namePtr
                  keySourcePtr
                  nullPtr
                  0
                if resultPtr == nullPtr
                  then do
                    err <- getLastError
                    return $ Left $ maybe "Unknown error" id err
                  else do
                    result <- peek resultPtr
                    let uuid = AccountId $ ffiUuidBytes result
                    rs_free_uuid resultPtr
                    return $ Right uuid

-- | List all account IDs in the wallet.
listAccounts :: FilePath -> Network -> IO (Either Text [AccountId])
listAccounts dbPath network = do
  let pathBS = TE.encodeUtf8 (pack dbPath)
  BSU.unsafeUseAsCStringLen pathBS $ \(pathPtr, pathLen) -> do
    resultPtr <- rs_list_accounts (castPtr pathPtr) (fromIntegral pathLen) (networkId network)
    if resultPtr == nullPtr
      then do
        err <- getLastError
        return $ Left $ maybe "Unknown error" id err
      else do
        result <- peek resultPtr
        let len = fromIntegral $ ffiAccountsLen result
        uuids <- if len > 0
          then do
            rawUuids <- peekArray len (ffiAccountsPtr result)
            return $ map (AccountId . ffiUuidBytes) rawUuids
          else return []
        rs_free_accounts resultPtr
        return $ Right uuids

-- | Get detailed information about an account.
getAccount :: FilePath -> Network -> AccountId -> IO (Either Text (Maybe Account))
getAccount dbPath network (AccountId uuid) = do
  let pathBS = TE.encodeUtf8 (pack dbPath)
  BSU.unsafeUseAsCStringLen pathBS $ \(pathPtr, pathLen) ->
    BSU.unsafeUseAsCStringLen uuid $ \(uuidPtr, _) -> do
      resultPtr <- rs_get_account
        (castPtr pathPtr) (fromIntegral pathLen)
        (networkId network)
        (castPtr uuidPtr)
      if resultPtr == nullPtr
        then return $ Right Nothing
        else do
          result <- peek resultPtr
          nameStr <- if ffiAccountName result /= nullPtr
            then Just . pack <$> peekCString (ffiAccountName result)
            else return $ Just ""
          keySourceStr <- if ffiAccountKeySource result /= nullPtr
            then Just . pack <$> peekCString (ffiAccountKeySource result)
            else return Nothing
          ufvkStr <- if ffiAccountUfvk result /= nullPtr
            then Just . pack <$> peekCString (ffiAccountUfvk result)
            else return Nothing
          uivkStr <- if ffiAccountUivk result /= nullPtr
            then Just . pack <$> peekCString (ffiAccountUivk result)
            else return Nothing
          let CBool hasSpend = ffiAccountHasSpendKey result
          rs_free_account resultPtr
          return $ Right $ Just Account
            { accountId = AccountId $ ffiUuidBytes $ ffiAccountUuid result
            , accountName = maybe "" id nameStr
            , accountKeySource = keySourceStr
            , accountUfvk = ufvkStr
            , accountUivk = uivkStr
            , accountHasSpendKey = hasSpend /= 0
            }

-- | Compute the seed fingerprint for a given seed.
seedFingerprint :: ByteString -> IO (Either Text ByteString)
seedFingerprint seed = do
  allocaBytes 32 $ \outputPtr -> do
    BSU.unsafeUseAsCStringLen seed $ \(seedPtr, seedLen) -> do
      CBool result <- rs_seed_fingerprint (castPtr seedPtr) (fromIntegral seedLen) outputPtr
      if result /= 0
        then Right <$> BS.packCStringLen (castPtr outputPtr, 32)
        else do
          err <- getLastError
          return $ Left $ maybe "Unknown error" id err

-- ============================================================================
-- Address Generation
-- ============================================================================

-- | Get the current default address for an account.
getCurrentAddress :: FilePath -> AccountId -> Network -> IO (Either Text (Maybe Text))
getCurrentAddress dbPath (AccountId uuid) network = do
  let pathBS = TE.encodeUtf8 (pack dbPath)
  BSU.unsafeUseAsCStringLen pathBS $ \(pathPtr, pathLen) ->
    BSU.unsafeUseAsCStringLen uuid $ \(uuidPtr, _) -> do
      resultPtr <- rs_get_current_address
        (castPtr pathPtr) (fromIntegral pathLen)
        (castPtr uuidPtr)
        (networkId network)
      if resultPtr == nullPtr
        then return $ Right Nothing
        else do
          addr <- pack <$> peekCString resultPtr
          rs_string_free resultPtr
          return $ Right $ Just addr

-- | Get the next available address for an account with specified receiver types.
getNextAvailableAddress
  :: FilePath
  -> AccountId
  -> Network
  -> ReceiverFlags
  -> IO (Either Text (Maybe Text))
getNextAvailableAddress dbPath (AccountId uuid) network flags = do
  let pathBS = TE.encodeUtf8 (pack dbPath)
  let request = (if receiverFlagsSapling flags then 0x2 else 0)
              + (if receiverFlagsOrchard flags then 0x4 else 0)
  BSU.unsafeUseAsCStringLen pathBS $ \(pathPtr, pathLen) ->
    BSU.unsafeUseAsCStringLen uuid $ \(uuidPtr, _) -> do
      resultPtr <- rs_get_next_available_address
        (castPtr pathPtr) (fromIntegral pathLen)
        (castPtr uuidPtr)
        (networkId network)
        request
      if resultPtr == nullPtr
        then return $ Right Nothing
        else do
          addr <- pack <$> peekCString resultPtr
          rs_string_free resultPtr
          return $ Right $ Just addr

-- ============================================================================
-- Address Validation
-- ============================================================================

-- | Check if an address is a valid shielded address for the given network.
isValidShieldedAddress :: Network -> Text -> IO Bool
isValidShieldedAddress network addr =
  withCString (unpack addr) $ \addrPtr -> do
    CBool result <- rs_is_valid_shielded_address addrPtr (networkId network)
    return $ result /= 0

-- ============================================================================
-- Wallet Summary
-- ============================================================================

-- | Get the wallet summary including all account balances and sync progress.
getWalletSummary :: FilePath -> Network -> Word32 -> IO (Either Text (Maybe WalletSummary))
getWalletSummary dbPath network minConfirmations = do
  let pathBS = TE.encodeUtf8 (pack dbPath)
  BSU.unsafeUseAsCStringLen pathBS $ \(pathPtr, pathLen) -> do
    resultPtr <- rs_get_wallet_summary
      (castPtr pathPtr) (fromIntegral pathLen)
      (networkId network)
      minConfirmations
    if resultPtr == nullPtr
      then return $ Right Nothing
      else do
        result <- peek resultPtr
        let balLen = fromIntegral $ ffiWalletSummaryBalancesLen result
        balances <- if balLen > 0
          then do
            rawBalances <- peekArray balLen (ffiWalletSummaryBalances result)
            return $ map convertBalance rawBalances
          else return []
        let chainTip = if ffiWalletSummaryChainTip result >= 0
              then Just $ BlockHeight $ fromIntegral $ ffiWalletSummaryChainTip result
              else Nothing
        let fullyScanned = if ffiWalletSummaryFullyScanned result >= 0
              then Just $ BlockHeight $ fromIntegral $ ffiWalletSummaryFullyScanned result
              else Nothing
        rs_free_wallet_summary resultPtr
        return $ Right $ Just WalletSummary
          { walletSummaryAccountBalances = balances
          , walletSummaryChainTipHeight = chainTip
          , walletSummaryFullyScannedHeight = fullyScanned
          , walletSummaryScanProgressNumerator = ffiWalletSummaryScanNumerator result
          , walletSummaryScanProgressDenominator = ffiWalletSummaryScanDenominator result
          , walletSummaryNextSaplingSubtreeIndex = ffiWalletSummaryNextSapling result
          , walletSummaryNextOrchardSubtreeIndex = ffiWalletSummaryNextOrchard result
          }
  where
    convertBalance :: FfiAccountBalance -> AccountBalance
    convertBalance ab = AccountBalance
      { accountBalanceId = AccountId $ ffiUuidBytes $ ffiAccountBalanceUuid ab
      , accountBalanceSapling = convertBal $ ffiAccountBalanceSapling ab
      , accountBalanceOrchard = convertBal $ ffiAccountBalanceOrchard ab
      }
    convertBal :: FfiBalance -> Balance
    convertBal fb = Balance
      { balanceSpendable = fromIntegral $ ffiBalanceSpendable fb
      , balanceChangePending = fromIntegral $ ffiBalanceChangePending fb
      , balanceValuePending = fromIntegral $ ffiBalanceValuePending fb
      }

-- ============================================================================
-- Blockchain Synchronization
-- ============================================================================

-- | Update the chain tip height in the wallet database.
updateChainTip :: FilePath -> BlockHeight -> Network -> IO (Either Text ())
updateChainTip dbPath (BlockHeight height) network = do
  let pathBS = TE.encodeUtf8 (pack dbPath)
  BSU.unsafeUseAsCStringLen pathBS $ \(pathPtr, pathLen) -> do
    CBool result <- rs_update_chain_tip
      (castPtr pathPtr) (fromIntegral pathLen)
      height
      (networkId network)
    if result /= 0
      then return $ Right ()
      else do
        err <- getLastError
        return $ Left $ maybe "Unknown error" id err

-- | Get the fully scanned height.
fullyScannedHeight :: FilePath -> Network -> IO (Either Text (Maybe BlockHeight))
fullyScannedHeight dbPath network = do
  let pathBS = TE.encodeUtf8 (pack dbPath)
  BSU.unsafeUseAsCStringLen pathBS $ \(pathPtr, pathLen) -> do
    result <- rs_fully_scanned_height
      (castPtr pathPtr) (fromIntegral pathLen)
      (networkId network)
    if result >= 0
      then return $ Right $ Just $ BlockHeight $ fromIntegral result
      else return $ Right Nothing

-- | Get the suggested scan ranges for syncing.
suggestScanRanges :: FilePath -> Network -> IO (Either Text [ScanRange])
suggestScanRanges dbPath network = do
  let pathBS = TE.encodeUtf8 (pack dbPath)
  BSU.unsafeUseAsCStringLen pathBS $ \(pathPtr, pathLen) -> do
    resultPtr <- rs_suggest_scan_ranges
      (castPtr pathPtr) (fromIntegral pathLen)
      (networkId network)
    if resultPtr == nullPtr
      then do
        err <- getLastError
        return $ Left $ maybe "Unknown error" id err
      else do
        result <- peek resultPtr
        let len = fromIntegral $ ffiScanRangesLen result
        ranges <- if len > 0
          then do
            rawRanges <- peekArray len (ffiScanRangesPtr result)
            return $ map convertRange rawRanges
          else return []
        rs_free_scan_ranges resultPtr
        return $ Right ranges
  where
    convertRange :: FfiScanRange -> ScanRange
    convertRange r = ScanRange
      { scanRangeStart = BlockHeight $ fromIntegral $ ffiScanRangeStart r
      , scanRangeEnd = BlockHeight $ fromIntegral $ ffiScanRangeEnd r
      , scanRangePriority = convertPriority $ ffiScanRangePriority r
      }
    convertPriority p = case p of
      0 -> Scanned
      1 -> Historic
      2 -> OpenAdjacent
      3 -> Verify
      4 -> FoundNote
      _ -> ChainTip

-- | Write block metadata to the filesystem block cache.
writeBlockMetadata :: FilePath -> [BlockMeta] -> IO (Either Text ())
writeBlockMetadata dbPath blocks = do
  let pathBS = TE.encodeUtf8 (pack dbPath)
  let ffiBlocks = map toFfiBlockMeta blocks
  BSU.unsafeUseAsCStringLen pathBS $ \(pathPtr, pathLen) ->
    withArray ffiBlocks $ \blocksPtr -> do
      CBool result <- rs_write_block_metadata
        (castPtr pathPtr) (fromIntegral pathLen)
        blocksPtr (fromIntegral $ length blocks)
      if result /= 0
        then return $ Right ()
        else do
          err <- getLastError
          return $ Left $ maybe "Unknown error" id err
  where
    toFfiBlockMeta :: BlockMeta -> FfiBlockMeta
    toFfiBlockMeta bm = FfiBlockMeta
      { ffiBlockMetaHeight = unBlockHeight $ blockMetaHeight bm
      , ffiBlockMetaHash = unBlockHash $ blockMetaHash bm
      , ffiBlockMetaTime = blockMetaTime bm
      , ffiBlockMetaSaplingOutputs = blockMetaSaplingOutputsCount bm
      , ffiBlockMetaOrchardActions = blockMetaOrchardActionsCount bm
      }

-- | Get the height of the latest cached block.
latestCachedBlockHeight :: FilePath -> IO (Either Text (Maybe BlockHeight))
latestCachedBlockHeight dbPath = do
  let pathBS = TE.encodeUtf8 (pack dbPath)
  BSU.unsafeUseAsCStringLen pathBS $ \(pathPtr, pathLen) -> do
    result <- rs_latest_cached_block_height (castPtr pathPtr) (fromIntegral pathLen)
    if result >= 0
      then return $ Right $ Just $ BlockHeight $ fromIntegral result
      else return $ Right Nothing

-- | Rewind the block cache to a given height.
rewindBlockCache :: FilePath -> BlockHeight -> IO (Either Text ())
rewindBlockCache dbPath (BlockHeight height) = do
  let pathBS = TE.encodeUtf8 (pack dbPath)
  BSU.unsafeUseAsCStringLen pathBS $ \(pathPtr, pathLen) -> do
    CBool result <- rs_rewind_fs_block_cache_to_height
      (castPtr pathPtr) (fromIntegral pathLen)
      height
    if result /= 0
      then return $ Right ()
      else do
        err <- getLastError
        return $ Left $ maybe "Unknown error" id err

-- | Put Sapling subtree roots into the wallet database.
putSaplingSubtreeRoots
  :: FilePath
  -> Word64           -- ^ Start index
  -> [SubtreeRoot]
  -> Network
  -> IO (Either Text ())
putSaplingSubtreeRoots dbPath startIndex roots network = do
  let pathBS = TE.encodeUtf8 (pack dbPath)
  let ffiRoots = map toFfiSubtreeRoot roots
  BSU.unsafeUseAsCStringLen pathBS $ \(pathPtr, pathLen) ->
    withArray ffiRoots $ \rootsPtr -> do
      CBool result <- rs_put_sapling_subtree_roots
        (castPtr pathPtr) (fromIntegral pathLen)
        startIndex
        rootsPtr (fromIntegral $ length roots)
        (networkId network)
      if result /= 0
        then return $ Right ()
        else do
          err <- getLastError
          return $ Left $ maybe "Unknown error" id err
  where
    toFfiSubtreeRoot :: SubtreeRoot -> FfiSubtreeRoot
    toFfiSubtreeRoot sr = FfiSubtreeRoot
      { ffiSubtreeRootHash = subtreeRootHash sr
      , ffiSubtreeRootHeight = unBlockHeight $ subtreeRootCompletingBlockHeight sr
      }

-- | Put Orchard subtree roots into the wallet database.
putOrchardSubtreeRoots
  :: FilePath
  -> Word64           -- ^ Start index
  -> [SubtreeRoot]
  -> Network
  -> IO (Either Text ())
putOrchardSubtreeRoots dbPath startIndex roots network = do
  let pathBS = TE.encodeUtf8 (pack dbPath)
  let ffiRoots = map toFfiSubtreeRoot roots
  BSU.unsafeUseAsCStringLen pathBS $ \(pathPtr, pathLen) ->
    withArray ffiRoots $ \rootsPtr -> do
      CBool result <- rs_put_orchard_subtree_roots
        (castPtr pathPtr) (fromIntegral pathLen)
        startIndex
        rootsPtr (fromIntegral $ length roots)
        (networkId network)
      if result /= 0
        then return $ Right ()
        else do
          err <- getLastError
          return $ Left $ maybe "Unknown error" id err
  where
    toFfiSubtreeRoot :: SubtreeRoot -> FfiSubtreeRoot
    toFfiSubtreeRoot sr = FfiSubtreeRoot
      { ffiSubtreeRootHash = subtreeRootHash sr
      , ffiSubtreeRootHeight = unBlockHeight $ subtreeRootCompletingBlockHeight sr
      }

-- ============================================================================
-- Transaction Proposals
-- ============================================================================

-- | Propose a transfer transaction.
-- Returns the serialized proposal protobuf.
proposeTransfer
  :: FilePath
  -> AccountId
  -> Text             -- ^ Recipient address
  -> Word64           -- ^ Amount in zatoshis
  -> Maybe ByteString -- ^ Optional memo
  -> Network
  -> Word32           -- ^ Minimum confirmations
  -> IO (Either Text ByteString)
proposeTransfer dbPath (AccountId uuid) toAddr value memo network minConf = do
  let pathBS = TE.encodeUtf8 (pack dbPath)
  BSU.unsafeUseAsCStringLen pathBS $ \(pathPtr, pathLen) ->
    BSU.unsafeUseAsCStringLen uuid $ \(uuidPtr, _) ->
      withCString (unpack toAddr) $ \addrPtr ->
        withMaybeBS memo $ \memoPtr memoLen -> do
          resultPtr <- rs_propose_transfer
            (castPtr pathPtr) (fromIntegral pathLen)
            (castPtr uuidPtr)
            addrPtr
            (fromIntegral value)
            memoPtr memoLen
            (networkId network)
            minConf
          if resultPtr == nullPtr
            then do
              err <- getLastError
              return $ Left $ maybe "Unknown error" id err
            else do
              result <- peek resultPtr
              let len = fromIntegral $ ffiBoxedSliceLen result
              proposal <- BS.packCStringLen (castPtr $ ffiBoxedSlicePtr result, len)
              rs_free_boxed_slice resultPtr
              return $ Right proposal

-- | Propose a transaction from a ZIP 321 payment URI.
-- Returns the serialized proposal protobuf.
proposeTransferFromUri
  :: FilePath
  -> AccountId
  -> Text             -- ^ Payment URI
  -> Network
  -> Word32           -- ^ Minimum confirmations
  -> IO (Either Text ByteString)
proposeTransferFromUri dbPath (AccountId uuid) uri network minConf = do
  let pathBS = TE.encodeUtf8 (pack dbPath)
  BSU.unsafeUseAsCStringLen pathBS $ \(pathPtr, pathLen) ->
    BSU.unsafeUseAsCStringLen uuid $ \(uuidPtr, _) ->
      withCString (unpack uri) $ \uriPtr -> do
        resultPtr <- rs_propose_transfer_from_uri
          (castPtr pathPtr) (fromIntegral pathLen)
          (castPtr uuidPtr)
          uriPtr
          (networkId network)
          minConf
        if resultPtr == nullPtr
          then do
            err <- getLastError
            return $ Left $ maybe "Unknown error" id err
          else do
            result <- peek resultPtr
            let len = fromIntegral $ ffiBoxedSliceLen result
            proposal <- BS.packCStringLen (castPtr $ ffiBoxedSlicePtr result, len)
            rs_free_boxed_slice resultPtr
            return $ Right proposal

-- ============================================================================
-- Transaction Creation
-- ============================================================================

-- | Create transactions from a proposal.
-- Returns the list of transaction IDs.
createProposedTransactions
  :: FilePath
  -> ByteString       -- ^ Proposal (serialized protobuf)
  -> ByteString       -- ^ USK (unified spending key)
  -> Network
  -> IO (Either Text [TxId])
createProposedTransactions dbPath proposal usk network = do
  let pathBS = TE.encodeUtf8 (pack dbPath)
  BSU.unsafeUseAsCStringLen pathBS $ \(pathPtr, pathLen) ->
    BSU.unsafeUseAsCStringLen proposal $ \(propPtr, propLen) ->
      BSU.unsafeUseAsCStringLen usk $ \(uskPtr, uskLen) -> do
        resultPtr <- rs_create_proposed_transactions
          (castPtr pathPtr) (fromIntegral pathLen)
          (castPtr propPtr) (fromIntegral propLen)
          (castPtr uskPtr) (fromIntegral uskLen)
          (networkId network)
        if resultPtr == nullPtr
          then do
            err <- getLastError
            return $ Left $ maybe "Unknown error" id err
          else do
            result <- peek resultPtr
            let len = fromIntegral $ ffiTxIdsLen result
            txids <- if len > 0
              then do
                -- Each txid is 32 bytes
                forM [0..len-1] $ \i -> do
                  let offset = i * 32
                  txidBytes <- BS.packCStringLen (castPtr (ffiTxIdsPtr result) `plusPtr` offset, 32)
                  return $ TxId txidBytes
              else return []
            rs_free_txids resultPtr
            return $ Right txids

-- ============================================================================
-- Transaction Data & Memos
-- ============================================================================

-- | Get a memo from a transaction output.
getMemo
  :: FilePath
  -> TxId
  -> Pool
  -> Word16           -- ^ Output index
  -> Network
  -> IO (Either Text (Maybe ByteString))
getMemo dbPath (TxId txid) pool outputIndex network = do
  let pathBS = TE.encodeUtf8 (pack dbPath)
  allocaBytes 512 $ \memoPtr ->
    BSU.unsafeUseAsCStringLen pathBS $ \(pathPtr, pathLen) ->
      BSU.unsafeUseAsCStringLen txid $ \(txidPtr, _) -> do
        CBool result <- rs_get_memo
          (castPtr pathPtr) (fromIntegral pathLen)
          (castPtr txidPtr)
          (poolId pool)
          outputIndex
          memoPtr
          (networkId network)
        if result /= 0
          then Right . Just <$> BS.packCStringLen (castPtr memoPtr, 512)
          else return $ Right Nothing

-- | Decrypt and store a transaction.
-- Returns the transaction ID if successful.
decryptAndStoreTransaction
  :: FilePath
  -> ByteString       -- ^ Transaction bytes
  -> Maybe BlockHeight -- ^ Mined height (Nothing for mempool)
  -> Network
  -> IO (Either Text (Maybe TxId))
decryptAndStoreTransaction dbPath txBytes minedHeight network = do
  let pathBS = TE.encodeUtf8 (pack dbPath)
  allocaBytes 32 $ \txidOut ->
    BSU.unsafeUseAsCStringLen pathBS $ \(pathPtr, pathLen) ->
      BSU.unsafeUseAsCStringLen txBytes $ \(txPtr, txLen) -> do
        let height = maybe (-1) (fromIntegral . unBlockHeight) minedHeight
        result <- rs_decrypt_and_store_transaction
          (castPtr pathPtr) (fromIntegral pathLen)
          (castPtr txPtr) (fromIntegral txLen)
          height
          (networkId network)
          txidOut
        case result of
          0 -> do
            txid <- BS.packCStringLen (castPtr txidOut, 32)
            return $ Right $ Just $ TxId txid
          1 -> return $ Right Nothing  -- Transaction already exists
          _ -> do
            err <- getLastError
            return $ Left $ maybe "Unknown error" id err

-- ============================================================================
-- Utilities
-- ============================================================================

-- | Get the branch ID for a given block height.
branchIdForHeight :: BlockHeight -> Network -> IO (Maybe Word32)
branchIdForHeight (BlockHeight height) network = do
  result <- rs_branch_id_for_height height (networkId network)
  if result == 0
    then return Nothing
    else return $ Just result

-- ============================================================================
-- Helper Functions
-- ============================================================================

withMaybeBS :: Maybe ByteString -> (Ptr Word8 -> CSize -> IO a) -> IO a
withMaybeBS Nothing f = f nullPtr 0
withMaybeBS (Just bs) f = BSU.unsafeUseAsCStringLen bs $ \(ptr, len) ->
  f (castPtr ptr) (fromIntegral len)

withMaybeCString :: Maybe Text -> (CString -> IO a) -> IO a
withMaybeCString Nothing f = f nullPtr
withMaybeCString (Just t) f = withCString (unpack t) f

-- plusPtr from Foreign.Ptr is imported at the top of the module
