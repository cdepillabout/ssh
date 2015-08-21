{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}

module SSH.Server.Types where

import Control.Lens (Lens', makeClassy)
import Network (PortNumber, Socket)

import SSH.Channel
import SSH.Session


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
