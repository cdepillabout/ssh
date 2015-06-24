{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}

module Test.SSH.Crypto (sshCryptoTests) where

#if __GLASGOW_HASKELL__ < 710
import Control.Applicative
#endif

import Control.Exception (ErrorCall(..), catchJust, evaluate)
import qualified Data.ByteString.Lazy as LBS
import Data.Word (Word8)
import System.IO.Unsafe (unsafePerformIO)
import Test.QuickCheck.Monadic (monadicIO, pick)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck (arbitrary, choose, testProperty, vectorOf)

import SSH.Crypto hiding (verify)
import qualified SSH.Crypto as Crypto

import Test.Util (ArbitraryLBS(..), assertM, publicKey)

--------------------
-- Helper Methods --
--------------------

-- | QuickCheck tests end up using unsafePerformIO because sign and verify
-- are in IO, which in turn is because the DSA operations are in IO,
-- but hopefully they only have benign side-effects if any

-- | Wrap 'Crypto.verify' in 'unsafePerformIO'.
verify :: PublicKey -> LBS.ByteString -> LBS.ByteString -> Bool
verify key message sig =
  unsafePerformIO $ catchJust sigErrors
                        (Crypto.verify key message sig >>= evaluate)
                        (\() -> return False)
  where
    sigErrors (ErrorCall msg)
      | msg == "signature representative out of range" = Just ()
    sigErrors _ = Nothing

-----------
-- Tests --
-----------

signThenVerifyTest :: TestTree
signThenVerifyTest =
    testProperty "signatures from sign work with verify" . monadicIO $ do
        keyPair <- pick arbitrary
        ArbitraryLBS message <- pick arbitrary
        digest <- Crypto.sign keyPair message
        assertM $ Crypto.verify (publicKey keyPair) message digest

signThenMutatedVerifyTest :: TestTree
signThenMutatedVerifyTest =
    testProperty "mutated signatures from sign fail with verify" . monadicIO $ do
        keyPair <- pick arbitrary
        ArbitraryLBS message <- pick arbitrary
        digest <- Crypto.sign keyPair message
        let pubKey = publicKey keyPair
            actualSignatureLen = fromIntegral $ actualSignatureLength pubKey
        offset <- pick $ choose ( LBS.length digest - actualSignatureLen
                                , LBS.length digest - 1 )
        mutation <- pick $ choose (1, 255 :: Word8)
        let mutatedSig = LBS.take offset digest `LBS.append`
                         LBS.pack [LBS.index digest offset + mutation] `LBS.append`
                         LBS.drop (offset+1) digest
        assertM $ not <$> Crypto.verify (publicKey keyPair) message mutatedSig

randomVerifyTest :: TestTree
randomVerifyTest =
    testProperty "random signatures fail with verify" $ monadicIO $ do
        keyPair <- pick arbitrary
        ArbitraryLBS message <- pick arbitrary
        -- might be sensible to test some other lengths, but the actual code
        -- just takes the last n bytes anyway, and it's not totally obvious
        -- what would be a good range of values to test with.
        sigBytes <- pick $ vectorOf (actualSignatureLength keyPair) arbitrary
        assertM $ not <$> Crypto.verify keyPair message (LBS.pack sigBytes)

sshCryptoTests :: TestTree
sshCryptoTests = testGroup "SSH/Crypto.hs tests"
    [ signThenVerifyTest
    , signThenMutatedVerifyTest
    , randomVerifyTest
    ]
