{-# LANGUAGE ForeignFunctionInterface #-}

module Lrzhs.Ffi where

import Data.Word (Word8)
import Foreign.C (CBool (..), CInt (..), CUInt (..))
import Foreign.C.String (CString)
import Foreign.C.Types (CChar)
import Foreign.Ptr (Ptr)
import Lrzhs.Types (Network (..))

foreign import ccall "lrzhs_is_valid_shielded_address"
  rs_is_valid_shielded_address :: CString -> CUInt -> IO CBool

foreign import ccall "lrzhs_derive_orchard_address"
  rs_derive_orchard_address :: CString -> Ptr Word8 -> CUInt -> IO (Ptr CChar)

foreign import ccall "lrzhs_string_free"
  rs_string_free :: Ptr CChar -> IO ()

foreign import ccall "lrzhs_last_error_length"
  rs_last_error_length :: IO CInt

foreign import ccall "lrzhs_error_message_utf8"
  rs_error_message_utf8 :: Ptr CChar -> CInt -> IO CInt

networkId :: Network -> CUInt
networkId = \case
  Mainnet -> CUInt 1
  Testnet -> CUInt 0
  Regtest -> CUInt 0
