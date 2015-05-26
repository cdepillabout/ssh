{-# LANGUAGE CPP #-}

module Test.SSH.Packet (sshPacketTests) where

#if __GLASGOW_HASKELL__ < 710
import Control.Applicative
#endif

import qualified Data.ByteString.Char8 as Char8
import Test.HUnit (assertBool)
import Test.QuickCheck (choose, elements, listOf)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase)
import Test.Tasty.QuickCheck (testProperty)

import SSH.Packet ()

import Test.Util (ArbitraryLazyByteString(..))

sshPacketTests :: TestTree
sshPacketTests = testGroup "SSH/Packet.hs tests"
    [
    ]

