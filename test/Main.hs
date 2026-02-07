module Main where

import System.Exit (exitFailure, exitSuccess)
import Lrzhs (isValidShieldedAddress)
import Lrzhs.Types (Network (..))

main :: IO ()
main = do
  results <- sequence
    [ test "valid Sapling address"
        True
        (isValidShieldedAddress Mainnet "zs1mrhc9y7jdh5r9ece8u5khgvj9kg0zgkxzdduyv0whkg7lkcrkx5xqem3e48avjq9wn2rukydkwn")
    , test "valid unified address (short)"
        True
        (isValidShieldedAddress Mainnet "u1l8xunezsvhq8fgzfl7404m450nwnd76zshscn6nfys7vyz2ywyh4cc5daaq0c7q2su5lqfh23sp7fkf3kt27ve5948mzpfdvckzaect2jtte308mkwlycj2u0eac077wu70vqcetkxf")
    , test "valid unified address (long)"
        True
        (isValidShieldedAddress Mainnet "u1pg2aaph7jp8rpf6yhsza25722sg5fcn3vaca6ze27hqjw7jvvhhuxkpcg0ge9xh6drsgdkda8qjq5chpehkcpxf87rnjryjqwymdheptpvnljqqrjqzjwkc2ma6hcq666kgwfytxwac8eyex6ndgr6ezte66706e3vaqrd25dzvzkc69kw0jgywtd0cmq52q5lkw6uh7hyvzjse8ksx")
    , test "invalid address (empty)"
        False
        (isValidShieldedAddress Mainnet "")
    , test "invalid address (garbage)"
        False
        (isValidShieldedAddress Mainnet "notanaddress")
    , test "invalid address (transparent)"
        False
        (isValidShieldedAddress Mainnet "t1Rv4exT7bqhZqi2j7xz8bUHDMxwosrjADU")
    , test "valid mainnet address on testnet"
        False
        (isValidShieldedAddress Testnet "zs1mrhc9y7jdh5r9ece8u5khgvj9kg0zgkxzdduyv0whkg7lkcrkx5xqem3e48avjq9wn2rukydkwn")
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
