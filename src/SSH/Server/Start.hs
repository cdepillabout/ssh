{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}

module SSH.Server.Start where

import Control.Exception.Lifted (bracket)
import Control.Lens ((^.), (.~), Lens', lens, view)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Control.Monad.Logger (MonadLogger, runStdoutLoggingT)
import Control.Monad.Random (MonadRandom)
import Control.Monad.Trans.Control (MonadBaseControl)
import Network (
    PortID(PortNumber), PortNumber, Socket, listenOn, sClose,
    )

import SSH.Channel
import SSH.Server.Loop
import SSH.Server.Types
import SSH.Session

createSetupConfig :: SessionConfig -> ChannelConfig -> PortNumber -> SetupConfig
createSetupConfig sessionConf channelConf portNumber =
    SetupConfig
        { _setupConfigSession = sessionConf
        , _setupConfigChannel = channelConf
        , _setupConfigPort = portNumber
        }

setupConfigToConfig :: Socket -> Lens' SetupConfig Config
setupConfigToConfig socket = lens getter setter
  where
    getter :: SetupConfig -> Config
    getter setupConf =
        Config (setupConf ^. sessionConfig) (setupConf ^. channelConfig) socket

    setter :: SetupConfig -> Config -> SetupConfig
    setter setupConf conf =
        sessionConfig .~ conf ^. sessionConfig $ channelConfig .~ conf ^. channelConfig $ setupConf

startedMessage :: MonadIO m => PortNumber -> m ()
startedMessage portNumber = do
        let portNumberString = show portNumber
        liftIO . putStrLn $ "ssh server listening on port " ++ portNumberString

runServer :: SSHServerM a -> IO a
runServer = runStdoutLoggingT . unSSHServerT

start :: forall m .
       ( MonadBaseControl IO m
       , MonadIO m
       , MonadLogger m
       , MonadRandom m
       )
      => SessionConfig
      -> ChannelConfig
      -> PortNumber
      -> m ()
start sessionConf channelConf port =
    let setupConf = createSetupConfig sessionConf channelConf port
    in startConfig readyAction setupConf
  where
    readyAction :: IO ()
    readyAction = startedMessage port

startConfig :: forall m .
             ( MonadBaseControl IO m
             , MonadIO m
             , MonadLogger m
             , MonadRandom m
             )
            => IO ()
            -> SetupConfig
            -> m ()
startConfig readyAction setupConf =
    -- waitLoop never actually exits so we could just use finally,
    -- but bracket seems more future proof
    bracket aquire release use
  where
    aquire :: m Socket
    aquire = liftIO . listenOn . PortNumber $ view setupConfigPort setupConf

    release :: Socket -> m ()
    release = liftIO . sClose

    use :: Socket -> m ()
    use socket = do
        liftIO $ readyAction
        let session = view setupConfigSession setupConf
        let channel = view setupConfigChannel setupConf
        waitLoop session channel socket

