{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Lrzhs.Types
  ( -- * Network
    Network (..)

    -- * Account
  , AccountId (..)
  , Account (..)
  , AccountPurpose (..)

    -- * Balance
  , Balance (..)
  , AccountBalance (..)
  , WalletSummary (..)

    -- * Block Types
  , BlockHeight (..)
  , BlockHash (..)
  , BlockMeta (..)

    -- * Scanning
  , ScanPriority (..)
  , ScanRange (..)
  , ScanSummary (..)

    -- * Transaction
  , TxId (..)
  , Pool (..)

    -- * Tree State
  , TreeState (..)
  , SubtreeRoot (..)

    -- * Receiver Flags
  , ReceiverFlags (..)
  , defaultReceiverFlags
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Text (Text)
import Data.Word (Word8, Word16, Word32, Word64)
import GHC.Generics (Generic)

-- | Zcash network type.
data Network
  = Mainnet
  | Testnet
  deriving (Eq, Show, Generic)

-- | Account identifier (UUID).
newtype AccountId = AccountId { unAccountId :: ByteString }
  deriving (Eq, Show)

-- | Account purpose for imported accounts.
data AccountPurpose
  = Spending
  | ViewOnly
  deriving (Eq, Show, Generic)

-- | Account information.
data Account = Account
  { accountId :: !AccountId
  , accountName :: !Text
  , accountKeySource :: !(Maybe Text)
  , accountUfvk :: !(Maybe Text)
  , accountUivk :: !(Maybe Text)
  , accountHasSpendKey :: !Bool
  } deriving (Eq, Show, Generic)

-- | Balance for a single pool.
data Balance = Balance
  { balanceSpendable :: !Word64
  , balanceChangePending :: !Word64
  , balanceValuePending :: !Word64
  } deriving (Eq, Show, Generic)

-- | Balance for a single account, broken down by pool.
data AccountBalance = AccountBalance
  { accountBalanceId :: !AccountId
  , accountBalanceSapling :: !Balance
  , accountBalanceOrchard :: !Balance
  } deriving (Eq, Show, Generic)

-- | Wallet summary with all account balances and sync progress.
data WalletSummary = WalletSummary
  { walletSummaryAccountBalances :: ![AccountBalance]
  , walletSummaryChainTipHeight :: !(Maybe BlockHeight)
  , walletSummaryFullyScannedHeight :: !(Maybe BlockHeight)
  , walletSummaryScanProgressNumerator :: !Word64
  , walletSummaryScanProgressDenominator :: !Word64
  , walletSummaryNextSaplingSubtreeIndex :: !Word64
  , walletSummaryNextOrchardSubtreeIndex :: !Word64
  } deriving (Eq, Show, Generic)

-- | Block height.
newtype BlockHeight = BlockHeight { unBlockHeight :: Word32 }
  deriving (Eq, Ord, Show, Num, Generic)

-- | Block hash (32 bytes).
newtype BlockHash = BlockHash { unBlockHash :: ByteString }
  deriving (Eq, Show)

-- | Block metadata for the block cache.
data BlockMeta = BlockMeta
  { blockMetaHeight :: !BlockHeight
  , blockMetaHash :: !BlockHash
  , blockMetaTime :: !Word32
  , blockMetaSaplingOutputsCount :: !Word32
  , blockMetaOrchardActionsCount :: !Word32
  } deriving (Eq, Show, Generic)

-- | Scan priority for a range.
data ScanPriority
  = Scanned
  | Historic
  | OpenAdjacent
  | Verify
  | FoundNote
  | ChainTip
  deriving (Eq, Ord, Show, Generic)

-- | A scan range with priority.
data ScanRange = ScanRange
  { scanRangeStart :: !BlockHeight
  , scanRangeEnd :: !BlockHeight
  , scanRangePriority :: !ScanPriority
  } deriving (Eq, Show, Generic)

-- | Summary of a block scanning operation.
data ScanSummary = ScanSummary
  { scanSummaryScannedStart :: !BlockHeight
  , scanSummaryScannedEnd :: !BlockHeight
  , scanSummaryScannedCount :: !Word64
  , scanSummaryReceivedNotes :: !Word64
  , scanSummarySpentNotes :: !Word64
  } deriving (Eq, Show, Generic)

-- | Transaction ID (32 bytes).
newtype TxId = TxId { unTxId :: ByteString }
  deriving (Eq, Show)

-- | Shielded pool type.
data Pool
  = Sapling
  | Orchard
  deriving (Eq, Show, Generic)

-- | Tree state for account birthday or recovery.
data TreeState = TreeState
  { treeStateHeight :: !BlockHeight
  , treeStateHash :: !BlockHash
  , treeStateTime :: !Word32
  , treeStateSaplingTree :: !(Maybe ByteString)
  , treeStateOrchardTree :: !(Maybe ByteString)
  } deriving (Eq, Show, Generic)

-- | Subtree root for commitment tree updates.
data SubtreeRoot = SubtreeRoot
  { subtreeRootHash :: !ByteString  -- ^ 32 bytes
  , subtreeRootCompletingBlockHeight :: !BlockHeight
  } deriving (Eq, Show, Generic)

-- | Receiver type flags for address generation.
data ReceiverFlags = ReceiverFlags
  { receiverFlagsSapling :: !Bool
  , receiverFlagsOrchard :: !Bool
  } deriving (Eq, Show, Generic)

-- | Default receiver flags (both Sapling and Orchard enabled).
defaultReceiverFlags :: ReceiverFlags
defaultReceiverFlags = ReceiverFlags True True
