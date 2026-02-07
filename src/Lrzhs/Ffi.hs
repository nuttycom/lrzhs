{-# LANGUAGE ForeignFunctionInterface #-}

module Lrzhs.Ffi where

import Data.Text (Text, unpack)
import Data.Word (Word32)
import Foreign.C (CBool (..), CUInt (..))
import Foreign.C.String (CString)
import Foreign.Ptr ()
import Lrzhs.Types (Network (..))

foreign import ccall "lrzhs_is_valid_shielded_address" rs_is_valid_shielded_address :: CString -> CUInt -> IO CBool

networkId :: Network -> CUInt
networkId = \case
  Mainnet -> CUInt 1
  Testnet -> CUInt 0
