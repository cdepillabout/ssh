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
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck (arbitrary, choose, forAll, testProperty, vectorOf)

import SSH.Crypto hiding (sign, verify)
import qualified SSH.Crypto as Crypto

import Test.Util (ArbitraryLBS(..), publicKey)

--------------------
-- Helper Methods --
--------------------

-- QuickCheck tests end up using unsafePerformIO because sign and verify
-- are in IO, which in turn is because the DSA operations are in IO,
-- but hopefully they only have benign side-effects if any

sign :: KeyPair -> LBS.ByteString -> LBS.ByteString
sign kp message = unsafePerformIO $ Crypto.sign kp message

verify :: PublicKey -> LBS.ByteString -> LBS.ByteString -> Bool
verify key message sig =
  unsafePerformIO $
    catchJust
      sigErrors
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
signThenVerifyTest = testProperty "signatures from sign work with verify" $
    \kp (ArbitraryLBS message) ->
        verify (publicKey kp) message $ sign kp message

signThenMutatedVerifyTest :: TestTree
signThenMutatedVerifyTest = testProperty "mutated signatures from sign fail with verify" $
  \kp (ArbitraryLBS message) ->
    let sig = sign kp message
        actualSignatureLen = fromIntegral $ actualSignatureLength (publicKey kp)
    in forAll (choose (LBS.length sig - actualSignatureLen, LBS.length sig - 1)) $ \offset ->
       forAll (choose (1, 255 :: Word8)) $ \mutation ->
       let mutatedSig =
             LBS.take offset sig `LBS.append`
             LBS.pack [LBS.index sig offset + mutation] `LBS.append`
             LBS.drop (offset+1) sig
       in not $ verify (publicKey kp) message mutatedSig

randomVerifyTest :: TestTree
randomVerifyTest = testProperty "random signatures fail with verify" $
    -- might be sensible to test some other lengths, but the actual code
    -- just takes the last n bytes anyway, and it's not totally obvious
    -- what would be a good range of values to test with.
    \key (ArbitraryLBS message) ->
        forAll (vectorOf (actualSignatureLength key) arbitrary) $
            \sigBytes ->
                not $ verify key message (LBS.pack sigBytes)


sshCryptoTests :: TestTree
sshCryptoTests = testGroup "SSH/Crypto.hs tests"
    [ signThenVerifyTest
    , signThenMutatedVerifyTest
    , randomVerifyTest
    ]
