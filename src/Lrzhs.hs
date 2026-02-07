module Lrzhs (isValidShieldedAddress) where

import Data.Text (Text, unpack)
import Foreign.C (CBool (..))
import Foreign.C.String (withCString)
import Lrzhs.Ffi (networkId, rs_is_valid_shielded_address)
import Lrzhs.Types (Network)

isValidShieldedAddress :: Network -> Text -> IO Bool
isValidShieldedAddress n t = fmap (\(CBool b) -> b /= 0) $ withCString (unpack t) (\cs -> rs_is_valid_shielded_address cs (networkId n))
