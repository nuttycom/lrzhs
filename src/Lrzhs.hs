module Lrzhs
  ( isValidShieldedAddress,
    deriveOrchardAddress,
    getLastError,
    DiversifierIndex (..),
    mkDiversifierIndex,
  )
where

import qualified Data.ByteString.Unsafe as BSU
import Data.Text (Text, pack, unpack)
import Foreign.C (CBool (..))
import Foreign.C.String (peekCString, withCString)
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Ptr (castPtr, nullPtr)
import Lrzhs.Ffi
  ( networkId,
    rs_derive_orchard_address,
    rs_error_message_utf8,
    rs_is_valid_shielded_address,
    rs_last_error_length,
    rs_string_free,
  )
import Lrzhs.Types (DiversifierIndex (..), Network, mkDiversifierIndex)

isValidShieldedAddress :: Network -> Text -> IO Bool
isValidShieldedAddress n t =
  fmap (\(CBool b) -> b /= 0) $
    withCString (unpack t) (\cs -> rs_is_valid_shielded_address cs (networkId n))

-- | Fetch the most recent error message recorded by the Rust layer.
getLastError :: IO Text
getLastError = do
  len <- rs_last_error_length
  if len <= 0
    then pure (pack "unknown error")
    else allocaBytes (fromIntegral len) $ \buf -> do
      written <- rs_error_message_utf8 buf len
      if written <= 0
        then pure (pack "unknown error")
        else pack <$> peekCString buf

-- | Derive a fresh Orchard-only Unified Address from a ZIP-316 Unified Incoming
-- Viewing Key at the given diversifier index. Returns 'Left' if the UIVK is
-- malformed, its network does not match, or it has no Orchard receiver.
deriveOrchardAddress :: Network -> Text -> DiversifierIndex -> IO (Either Text Text)
deriveOrchardAddress n uivk (DiversifierIndex idx) =
  withCString (unpack uivk) $ \uivkPtr ->
    BSU.unsafeUseAsCStringLen idx $ \(idxPtr, _) -> do
      resultPtr <- rs_derive_orchard_address uivkPtr (castPtr idxPtr) (networkId n)
      if resultPtr == nullPtr
        then Left <$> getLastError
        else do
          addr <- pack <$> peekCString resultPtr
          rs_string_free resultPtr
          pure (Right addr)
