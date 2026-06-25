module Main where

import qualified Data.ByteString as BS
import Data.Either (isLeft)
import Data.Maybe (fromJust)
import Data.Text (Text)
import qualified Data.Text as T
import Lrzhs (deriveOrchardAddress, isValidShieldedAddress, mkDiversifierIndex)
import Lrzhs.Types (Network (..))
import System.Exit (exitFailure, exitSuccess)

main :: IO ()
main = do
  let zeroIdx = fromJust (mkDiversifierIndex (BS.replicate 11 0))
      testUivk = "uivk1ewu2n4n4xgwxvem5krz36flunule40kyss82myn583hj9ypsrmt34yw3t5h6utkcx45w3tcharxck5fzurycymxp408wxh7f7u2snqdekm8d9au580fvm7yj9y3qsw7d4l9qsmsz98" :: Text
      expectedUa = "u1u4zdvtcrjt4cnffw3shrx440754g0mhr4a7fenck686tfr6rdqy9wu5v39ydpgm4ut37qnlh9kpw9fsp8wcwyu2y2r5stjhj0qwfnmrq" :: Text
  results <-
    sequence
      [ test
          "valid Sapling address"
          True
          (isValidShieldedAddress Mainnet "zs1mrhc9y7jdh5r9ece8u5khgvj9kg0zgkxzdduyv0whkg7lkcrkx5xqem3e48avjq9wn2rukydkwn"),
        test
          "valid unified address (short)"
          True
          (isValidShieldedAddress Mainnet "u1l8xunezsvhq8fgzfl7404m450nwnd76zshscn6nfys7vyz2ywyh4cc5daaq0c7q2su5lqfh23sp7fkf3kt27ve5948mzpfdvckzaect2jtte308mkwlycj2u0eac077wu70vqcetkxf"),
        test
          "valid unified address (long)"
          True
          (isValidShieldedAddress Mainnet "u1pg2aaph7jp8rpf6yhsza25722sg5fcn3vaca6ze27hqjw7jvvhhuxkpcg0ge9xh6drsgdkda8qjq5chpehkcpxf87rnjryjqwymdheptpvnljqqrjqzjwkc2ma6hcq666kgwfytxwac8eyex6ndgr6ezte66706e3vaqrd25dzvzkc69kw0jgywtd0cmq52q5lkw6uh7hyvzjse8ksx"),
        test
          "invalid address (empty)"
          False
          (isValidShieldedAddress Mainnet ""),
        test
          "invalid address (garbage)"
          False
          (isValidShieldedAddress Mainnet "notanaddress"),
        test
          "invalid address (transparent)"
          False
          (isValidShieldedAddress Mainnet "t1Rv4exT7bqhZqi2j7xz8bUHDMxwosrjADU"),
        test
          "valid mainnet address on testnet"
          False
          (isValidShieldedAddress Testnet "zs1mrhc9y7jdh5r9ece8u5khgvj9kg0zgkxzdduyv0whkg7lkcrkx5xqem3e48avjq9wn2rukydkwn"),
        testEq
          "derive Orchard-only address at index 0 (mainnet)"
          (Right expectedUa)
          (deriveOrchardAddress Mainnet testUivk zeroIdx),
        test
          "derive rejects a malformed UIVK"
          True
          (isLeft <$> deriveOrchardAddress Mainnet "not-a-uivk" zeroIdx),
        test
          "derive rejects a network mismatch"
          True
          (isLeft <$> deriveOrchardAddress Testnet testUivk zeroIdx),
        test
          "derive error message is NUL-free"
          True
          (either (T.all (/= '\NUL')) (const False) <$> deriveOrchardAddress Mainnet "not-a-uivk" zeroIdx)
      ]
  if and results then exitSuccess else exitFailure

test :: String -> Bool -> IO Bool -> IO Bool
test name expected action = do
  result <- action
  if result == expected
    then do
      putStrLn $ "  PASS: " ++ name
      pure True
    else do
      putStrLn $ "  FAIL: " ++ name ++ " (expected " ++ show expected ++ ", got " ++ show result ++ ")"
      pure False

testEq :: (Eq a, Show a) => String -> a -> IO a -> IO Bool
testEq name expected action = do
  result <- action
  if result == expected
    then do
      putStrLn $ "  PASS: " ++ name
      pure True
    else do
      putStrLn $ "  FAIL: " ++ name ++ " (expected " ++ show expected ++ ", got " ++ show result ++ ")"
      pure False
