{-# LANGUAGE CPP #-}
{-# LANGUAGE TemplateHaskell #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Main where

import Test.Tasty
    (TestTree, defaultMain, testGroup, withResource
    )
import Test.Tasty.HUnit (testCase)
import Test.Tasty.QuickCheck (testProperty)
import Test.HUnit (assertBool)
import Test.QuickCheck
    (Arbitrary(..), elements, forAll, choose, vectorOf
    )

#if __GLASGOW_HASKELL__ < 710
import Control.Applicative
#endif

import Control.Concurrent (forkIO, killThread)
import Control.Concurrent.MVar (newEmptyMVar, takeMVar, putMVar)
import Control.Exception (bracket, try, catchJust, ErrorCall(..), evaluate)
import Control.Monad (when)
import Data.ByteString.Char8 (pack)
import qualified Data.ByteString.Lazy as LBS
import Data.List (isSuffixOf)
import Data.Map (Map)
import qualified Data.Map as Map
import Data.Word (Word8)
import System.Directory (createDirectoryIfMissing, removeFile)
import System.FilePath ((<.>))
import System.IO (hPutStr, openTempFile, hClose)
import System.IO.Unsafe (unsafePerformIO)

import Network.SSH.Client.LibSSH2
import Network.SSH.Client.LibSSH2.Errors
import Network.SSH.Client.LibSSH2.Foreign

import qualified SSH
import SSH.Channel
import SSH.Crypto hiding (sign, verify)
import qualified SSH.Crypto as Crypto
import SSH.Session

import EmbedTree

keysDirectory :: Map String Entry
keysDirectory = getDirectory $(embedTree "keys")

sshPort :: Num a => a -- used as an Int or a PortNumber
sshPort = 5032

withOneUserServer :: KeyPair -> PublicKey -> TestTree -> TestTree
withOneUserServer hostKp acceptedKey test =
    withResource
        (do startedSignal <- newEmptyMVar
            tid <- forkIO $ SSH.startConfig (config startedSignal)
            takeMVar startedSignal
            return tid
        )
        killThread
        (const test)
  where
    config startedSignal =
        SSH.Config
          { SSH.cSession = session
          , SSH.cChannel = channel
          , SSH.cPort = sshPort
          , SSH.cReadyAction = putMVar startedSignal ()
          }

    session =
        SessionConfig
          { scAuthMethods = ["publickey", "password"]
          , scAuthorize = sshAuthorize
          , scKeyPair = hostKp
          }

    channel =
        ChannelConfig
          { ccRequestHandler = channelRequest
          }

    sshAuthorize (PublicKey "testuser" k) = return (k == acceptedKey)
    sshAuthorize _ = return False

    channelRequest wr (Execute "check") = do
        channelMessage "checked"
        when wr channelSuccess
        channelDone

    channelRequest wr cmd = do
        channelError $ "<" ++ show cmd ++ "> not supported"
        when wr channelFail

withTextInTempFile :: String -> String -> (FilePath -> IO a) -> IO a
withTextInTempFile nameTemplate contents action = do
    let tempFolder = "temp"
    createDirectoryIfMissing False tempFolder
    bracket
        (do
            (f, h) <- openTempFile tempFolder nameTemplate
            hPutStr h contents
            hClose h
            return f
        )
        removeFile
        action

data AuthResult = OK | Error ErrorCode
    deriving (Show, Eq)

authWith :: String -> KeyPair -> IO AuthResult
authWith publicKeyText privateKeyPair =
    withTextInTempFile "private" (printKeyPair privateKeyPair) $ \privateKeyFile ->
        withTextInTempFile "public" publicKeyText $ \publicKeyFile ->
            withSession "localhost" sshPort $ \session -> do
                authResult <- try $ publicKeyAuthFile session
                                                      "testuser"
                                                      publicKeyFile
                                                      privateKeyFile
                                                      ""
                case authResult of
                    Left e -> return $ Error e
                    Right () -> do
                        channel <- openChannelSession session
                        channelExecute channel "check"
                        checked <- readChannel channel 20
                        when (checked /= pack "checked\r\n") $
                            fail "incorrect check result"
                        return OK

breakPrivateKey :: KeyPair -> KeyPair
-- This leaves enough information intact to reconstruct the private key
-- (e.g the primes), but in practice it seems to be enough to cause an
-- authentication failure.
-- Changing the numbers too much can cause segfaults or out of range signatures
breakPrivateKey kp@RSAKeyPair {} =
   kp
   { rprivD = rprivD kp - 2
   , rprivPrime1 = rprivPrime1 kp - 2
   , rprivPrime2 = rprivPrime2 kp - 2
   , rprivExponent1 = rprivExponent1 kp - 2
   , rprivExponent2 = rprivExponent2 kp - 2
   , rprivCoefficient = rprivCoefficient kp - 2
   }
breakPrivateKey kp@DSAKeyPair {} = kp { dprivX = 1 }

publicKey :: KeyPair -> PublicKey
publicKey (RSAKeyPair { rprivPub = k }) = k
publicKey (DSAKeyPair { dprivPub = k }) = k

hostKeyPair :: KeyPair
hostKeyPair = parseKeyPair . getFile $ getEntry "host" keysDirectory

clientKeysDirectory :: Map String Entry
clientKeysDirectory = getDirectory $ getEntry "client" keysDirectory

getClientPublicKeyFileText :: String -> String
getClientPublicKeyFileText keyName = getFile $ getEntry (keyName <.> "pub") clientKeysDirectory

getClientPrivateKeyPair :: String -> KeyPair
getClientPrivateKeyPair keyName = parseKeyPair . getFile $ getEntry keyName clientKeysDirectory

privateKeyPairFiles :: [String]
privateKeyPairFiles = filter (not . isSuffixOf "pub") $ Map.keys clientKeysDirectory

singleKeyAuthTests :: TestTree
singleKeyAuthTests =
  testGroup "Single key auth tests"
    [
      let publicKeyFileText = getClientPublicKeyFileText privateKeyPairFile
          privateKeyPair = getClientPrivateKeyPair privateKeyPairFile
      in
        withOneUserServer hostKeyPair (publicKey privateKeyPair) $
          testGroup ("Check auth with " ++ privateKeyPairFile)
          [
            testCase "Works" $ do
              authResult <- authWith publicKeyFileText privateKeyPair
              assertBool "should auth with correct private key" (OK == authResult)

          , testCase "Fails with broken private key" $ do
              authResult <- authWith publicKeyFileText
                                     (breakPrivateKey privateKeyPair)
              assertBool "shouldn't auth with broken private key"
                         (Error PUBLICKEY_UNVERIFIED == authResult)
          ]

    | privateKeyPairFile <- privateKeyPairFiles

    ]

wrongKeyAuthTest :: TestTree
wrongKeyAuthTest =
  withOneUserServer hostKeyPair (publicKey rightPrivateKeyPair) $
  testCase "Check auth failure with wrong key" $ do
      authResult <- authWith wrongPublicKeyFileText wrongPrivateKeyPair
      assertBool "shouldn't auth with wrong private key"
                 (Error AUTHENTICATION_FAILED == authResult)
  where
    rightPrivateKeyPair = getClientPrivateKeyPair "id_rsa_test"
    wrongPrivateKeyPair = getClientPrivateKeyPair "id_rsa_test2"
    wrongPublicKeyFileText = getClientPublicKeyFileText "id_rsa_test2"

instance Arbitrary LBS.ByteString where
  arbitrary = LBS.pack <$> arbitrary

instance Arbitrary KeyPair where
  arbitrary = elements $ map getClientPrivateKeyPair privateKeyPairFiles

instance Arbitrary PublicKey where
  arbitrary = publicKey <$> arbitrary

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


signThenVerifyTest :: TestTree
signThenVerifyTest = testProperty "signatures from sign work with verify" $
  \kp message -> verify (publicKey kp) message $ sign kp message

signThenMutatedVerifyTest :: TestTree
signThenMutatedVerifyTest = testProperty "mutated signatures from sign fail with verify" $
  \kp message ->
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
  \key message -> forAll (vectorOf (actualSignatureLength key) arbitrary) $ \sigBytes ->
    not $ verify key message (LBS.pack sigBytes)


allTests :: TestTree
allTests =
  testGroup "Tests"
  [ testGroup "With server"
    [ singleKeyAuthTests
    , wrongKeyAuthTest
    ]
  , testGroup "Signatures"
    [ signThenVerifyTest
    , signThenMutatedVerifyTest
    , randomVerifyTest
    ]
  ]


main :: IO ()
main = defaultMain allTests
