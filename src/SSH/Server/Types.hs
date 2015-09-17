{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}

module SSH.Server.Types where

import Control.Lens (Lens', makeClassy)
import Control.Monad.Base (MonadBase(..), liftBaseDefault)
import Control.Monad.IO.Class (MonadIO)
import Control.Monad.Logger (LoggingT, MonadLogger)
import Control.Monad.Random (MonadRandom(..))
import Control.Monad.Trans.Class (MonadTrans, lift)
import Control.Monad.Trans.Control (
    ComposeSt, MonadBaseControl(..), MonadTransControl(..), Run, RunInBase,
    defaultLiftBaseWith, defaultLiftWith, defaultRestoreM, defaultRestoreT
    )
import Network (PortNumber, Socket)

import SSH.Channel
import SSH.Session

type SSHServerM = SSHServerT IO

newtype SSHServerT m a = SSHServerT { unSSHServerT :: LoggingT m a }
    deriving ( Applicative
             , Functor
             , Monad
             , MonadIO
             , MonadLogger
             , MonadTrans
             )

instance MonadRandom m => MonadRandom (SSHServerT m) where
    getRandom   = lift getRandom
    {-# INLINE getRandom #-}
    getRandoms  = lift getRandoms
    {-# INLINE getRandoms #-}
    getRandomR  = lift . getRandomR
    {-# INLINE getRandomR #-}
    getRandomRs = lift . getRandomRs
    {-# INLINE getRandomRs #-}

instance MonadTransControl SSHServerT where
    type StT SSHServerT a = StT LoggingT a

    liftWith :: Monad m => (Run SSHServerT -> m a) -> SSHServerT m a
    liftWith = defaultLiftWith SSHServerT unSSHServerT

    restoreT :: Monad m => m a -> SSHServerT m a
    restoreT = defaultRestoreT SSHServerT

instance MonadBase IO (SSHServerT IO) where
    liftBase :: IO a -> SSHServerT IO a
    liftBase = liftBaseDefault

instance MonadBaseControl IO (SSHServerT IO) where
    type StM (SSHServerT IO) a = ComposeSt SSHServerT IO a

    liftBaseWith :: (RunInBase (SSHServerT IO) IO -> IO a) -> SSHServerT IO a
    liftBaseWith = defaultLiftBaseWith

    restoreM :: ComposeSt SSHServerT IO a -> SSHServerT IO a
    restoreM = defaultRestoreM

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
