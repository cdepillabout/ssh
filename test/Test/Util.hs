{-# LANGUAGE CPP #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TemplateHaskell #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Test.Util where

#if __GLASGOW_HASKELL__ < 710
import Control.Applicative
#endif

import qualified Data.ByteString.Lazy as LBS
import Data.List (isSuffixOf)
import Data.Map (Map)
import qualified Data.Map as Map
import System.FilePath ((<.>))
import Test.Tasty.QuickCheck (Arbitrary(..), elements, suchThat)

import SSH.Crypto (KeyPair(..), PublicKey(..), parseKeyPair)

import Test.Util.EmbedTree (Entry(..), embedTree, getDirectory, getEntry, getFile)

-- | Arbitrary instances for 'LBS.ByteString'.

newtype ArbitraryLBS = ArbitraryLBS LBS.ByteString
    deriving Show

instance Arbitrary ArbitraryLBS where
    arbitrary = ArbitraryLBS . LBS.pack <$> arbitrary

newtype ArbitraryNonEmptyLBS = ArbitraryNonEmptyLBS LBS.ByteString
    deriving Show

instance Arbitrary ArbitraryNonEmptyLBS where
    arbitrary =
        let nonEmptyString = suchThat arbitrary $ not . null
        in ArbitraryNonEmptyLBS . LBS.pack <$> nonEmptyString

-- | Arbitrary instances for 'KeyPair' and 'PublicKey'.

instance Arbitrary KeyPair where
  arbitrary = elements clientPrivateKeyPairs

instance Arbitrary PublicKey where
  arbitrary = do
      arbitraryKeyPair <- arbitrary
      return $ publicKey arbitraryKeyPair

----------------------
-- Helper functions --
----------------------

-- | Extract a PublicKey from a KeyPair.
publicKey :: KeyPair -> PublicKey
publicKey RSAKeyPair{..} = rprivPub
publicKey DSAKeyPair{..} = dprivPub

---------------------------------------------------------------------
-- Helper functions for working with test data in @keys@ directory --
---------------------------------------------------------------------

-- | A directory map from filenames to 'Entry' for the @test/keys/@
-- directory.
keysDirectory :: Map String Entry
keysDirectory = getDirectory $(embedTree "../../keys")

-- | A 'KeyPair' from the file @test/keys/host@.
hostKeyPair :: KeyPair
hostKeyPair = parseKeyPair . getFile $ getEntry "host" keysDirectory

-- | A directory map from filenames to 'Entry' for the @test/keys/client/@
-- directory.
clientKeysDirectory :: Map String Entry
clientKeysDirectory = getDirectory $ getEntry "client" keysDirectory

-- | Return the contents of the the public key file @keyName.pub@ from the
-- @test/keys/client/@ directory.
getClientPublicKeyFileText :: String -> String
getClientPublicKeyFileText keyName = getFile $ getEntry (keyName <.> "pub") clientKeysDirectory

-- | Return the contents of the the public/private key pair file @keyName@
-- from the @test/keys/client/@ directory.
getClientPrivateKeyPair :: String -> KeyPair
getClientPrivateKeyPair keyName = parseKeyPair . getFile $ getEntry keyName clientKeysDirectory

-- | List of all filenames for files from the @test/keys/client/@
-- directory.
privateKeyPairFiles :: [String]
privateKeyPairFiles = filter (not . isSuffixOf "pub") $ Map.keys clientKeysDirectory

-- | List of all 'KeyPair's from 'privateKeyPairFiles'.
clientPrivateKeyPairs :: [KeyPair]
clientPrivateKeyPairs = map getClientPrivateKeyPair privateKeyPairFiles
