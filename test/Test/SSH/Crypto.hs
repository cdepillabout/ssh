{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}

module Test.SSH.Crypto (sshCryptoTests) where

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

signThenVerifyTest :: TestTree
signThenVerifyTest =
    testProperty "signatures from sign work with verify" . monadicIO $ do
        keyPair <- pick arbitrary
        ArbitraryLBS message <- pick arbitrary
        digest <- sign keyPair message
        assertM $ verify (publicKey keyPair) message digest

signThenMutatedVerifyTest :: TestTree
signThenMutatedVerifyTest =
    testProperty "mutated signatures from sign fail with verify" . monadicIO $ do
        keyPair <- pick arbitrary
        ArbitraryLBS message <- pick arbitrary
        digest <- sign keyPair message
        let pubKey = publicKey keyPair
            actualSignatureLen = fromIntegral $ actualSignatureLength pubKey
        offset <- pick $ choose ( LBS.length digest - actualSignatureLen
                                , LBS.length digest - 1 )
        mutation <- pick $ choose (1, 255 :: Word8)
        let mutatedSig = LBS.take offset digest `LBS.append`
                         LBS.pack [LBS.index digest offset + mutation] `LBS.append`
                         LBS.drop (offset+1) digest
        assertM $ not <$> verify (publicKey keyPair) message mutatedSig

randomVerifyTest :: TestTree
randomVerifyTest =
    testProperty "random signatures fail with verify" . monadicIO $ do
        keyPair <- pick arbitrary
        ArbitraryLBS message <- pick arbitrary
        -- might be sensible to test some other lengths, but the actual code
        -- just takes the last n bytes anyway, and it's not totally obvious
        -- what would be a good range of values to test with.
        sigBytes <- pick $ vectorOf (actualSignatureLength keyPair) arbitrary
        assertM $ not <$> verify keyPair message (LBS.pack sigBytes)

sshCryptoTests :: TestTree
sshCryptoTests = testGroup "SSH/Crypto.hs tests"
    [ signThenVerifyTest
    , signThenMutatedVerifyTest
    , randomVerifyTest
    ]
