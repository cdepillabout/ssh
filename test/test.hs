{-# LANGUAGE CPP #-}

module Main where

#if __GLASGOW_HASKELL__ < 710
import Control.Applicative
#endif

import Control.Concurrent (forkIO, killThread)
import Control.Concurrent.MVar (newEmptyMVar, takeMVar, putMVar)
import Control.Exception (bracket, try)
import Control.Monad (when)
import Data.ByteString.Char8 (pack)
import System.Directory (createDirectoryIfMissing, removeFile)
import System.IO (hPutStr, openTempFile, hClose)
import Test.Tasty (TestTree, defaultMain, testGroup, withResource)
import Test.Tasty.HUnit (assertBool, testCase)

import Network.SSH.Client.LibSSH2
import Network.SSH.Client.LibSSH2.Errors
import Network.SSH.Client.LibSSH2.Foreign

import qualified SSH
import SSH.Channel
import SSH.Crypto
import SSH.Session

import Test.SSH.Crypto (sshCryptoTests)
import Test.SSH.Internal.Util (sshInternalUtilTests)
import Test.SSH.Packet (sshPacketTests)
import Test.SSH.NetReader (sshNetReaderTests)
import Test.Util
    ( getClientPrivateKeyPair, getClientPublicKeyFileText, hostKeyPair, privateKeyPairFiles, publicKey)

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

allTests :: TestTree
allTests =
    testGroup "Tests"
        [ testGroup "With server"
            [ singleKeyAuthTests
            , wrongKeyAuthTest
            ]
        , sshInternalUtilTests
        , sshPacketTests
        , sshNetReaderTests
        , sshCryptoTests
        ]

main :: IO ()
main = defaultMain allTests
