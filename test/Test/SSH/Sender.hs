{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}

module Test.SSH.Sender (sshSenderTests) where

#if __GLASGOW_HASKELL__ < 710
import Control.Applicative
#endif

import qualified Data.ByteString.Lazy as LBS
import Data.Word (Word8)
import Test.QuickCheck.Monadic (monadicIO, pick)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck (arbitrary, choose, testProperty, vectorOf)

import SSH.Crypto

import Test.Util (ArbitraryLBS(..), assertM, publicKey)

-----------
-- Tests --
-----------

blahblahTest :: TestTree
blahblahTest = undefined

sshSenderTests :: TestTree
sshSenderTests = testGroup "SSH/Sender.hs tests"
    [
    ]
