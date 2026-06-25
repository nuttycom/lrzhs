module Lrzhs.Types
  ( Network (..),
    DiversifierIndex (..),
    mkDiversifierIndex,
  )
where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS

data Network
  = Mainnet
  | Testnet
  | Regtest

-- | An 88-bit (11-byte) Orchard diversifier index. Construct only via
-- 'mkDiversifierIndex', which enforces the length invariant.
newtype DiversifierIndex = DiversifierIndex {diversifierIndexBytes :: ByteString}
  deriving (Eq, Show)

-- | Build a 'DiversifierIndex' from exactly 11 bytes; 'Nothing' otherwise.
mkDiversifierIndex :: ByteString -> Maybe DiversifierIndex
mkDiversifierIndex bs
  | BS.length bs == 11 = Just (DiversifierIndex bs)
  | otherwise = Nothing
