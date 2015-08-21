{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}

module SSH.Server.Types where

import Control.Concurrent (forkIO)
import Control.Concurrent.Chan (newChan, writeChan)
import Control.Exception.Lifted (bracket)
import Control.Lens ((^.), (.~), Lens', lens, makeClassy, set, view)
import Control.Monad (replicateM)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Control.Monad.Reader (ReaderT, runReaderT)
import Control.Monad.Reader.Class (MonadReader, asks)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Control (MonadBaseControl)
import Control.Monad.Trans.State (evalStateT, get, gets, modify)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Data.Digest.Pure.SHA (bytestringDigest, sha1)
import qualified Data.Map as M
import qualified Data.Serialize as S
import Crypto.HMAC (MacKey(..), hmac)
import Crypto.Hash.CryptoAPI (MD5, SHA1)
import Data.List (intercalate)
import Data.List.Split (splitOn)
import Network (
    PortID(PortNumber), PortNumber, Socket, accept,listenOn, sClose,
    )
import OpenSSL.BN (randIntegerOneToNMinusOne, modexp)
import System.IO (hFlush, hGetLine, hIsEOF, hPutStr, hSetBinaryMode)
import System.Random (randomRIO)

import SSH.Channel
import SSH.Crypto
import SSH.Debug
import SSH.NetReader
import SSH.Packet
import SSH.Sender
import SSH.Session
import SSH.Internal.Util


data SetupConfig =
    SetupConfig {
        _setupConfigSession :: SessionConfig,
        _setupConfigChannel :: ChannelConfig,
        _setupConfigPort    :: PortNumber
    }
makeClassy ''SetupConfig

data Config =
    Config {
        _configSession :: SessionConfig,
        _configChannel :: ChannelConfig,
        _configSocket  :: Socket
    }
makeClassy ''Config

class HasSessionConfig a where
    sessionConfig :: Lens' a SessionConfig

instance HasSessionConfig SessionConfig where
    sessionConfig = id
instance HasSessionConfig SetupConfig where
    sessionConfig = setupConfigSession
instance HasSessionConfig Config where
    sessionConfig = configSession

class HasChannelConfig a where
    channelConfig :: Lens' a ChannelConfig

instance HasChannelConfig ChannelConfig where
    channelConfig = id
instance HasChannelConfig SetupConfig where
    channelConfig = setupConfigChannel
instance HasChannelConfig Config where
    channelConfig = configChannel
