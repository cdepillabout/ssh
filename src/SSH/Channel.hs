{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE TypeSynonymInstances #-}
module SSH.Channel where

import Control.Concurrent
import Control.Exception
import Control.Monad (void, when)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.State
import Data.Word
import System.Exit
import System.IO
import System.Process (ProcessHandle, runInteractiveCommand,
                       terminateProcess, waitForProcess,)
import qualified Data.ByteString.Lazy as LBS

import SSH.Debug
import SSH.Packet
import SSH.Sender

-- | Type that represents an SSH channel.
type Channel = StateT ChannelState IO

-- | The current state of the SSH channel.
data ChannelState =
    ChannelState
        { csConfig :: ChannelConfig        -- ^ 'ChannelConfig' for this
                                           -- channel.
        , csID :: Word32                   -- ^ Our ID for this channel.
        , csTheirID :: Word32              -- ^ Client's ID for this channel.
        , csSend :: SenderMessage -> IO () -- ^ Function that will actually
                                           -- send a message.  This will
                                           -- probably be the same as the
                                           -- 'ssSend' function from the
                                           -- 'SessionState' type.
        , csDataReceived :: Word32         -- ^ Data received so far in this
                                           -- window.
                                           --
                                           -- __TODO__ Make sure this
                                           -- documentation is correct.
        , csMaxPacket :: Word32            -- ^ Max packet size that is allowed
                                           -- for this channel.
                                           --
                                           -- __TODO__ Fix this documentation.
        , csWindowSize :: Word32           -- ^ Current window size for us.
                                           --
                                           -- __TODO__ Make sure this is
                                           -- correct.
        , csTheirWindowSize :: Word32      -- ^ Current window size for the
                                           -- client.
                                           --
                                           -- __TODO__ Make sure this is
                                           -- correct.
        , csUser :: String                 -- ^ Username of the authenticated
                                           -- user.
        , csProcess :: Maybe Process       -- ^ Information for the current
                                           -- running 'Process' for an
                                           -- 'Exec' channel.
        , csRedirector :: Maybe ThreadId   -- ^ __TODO__ What is this?
        }

data ChannelMessage
    = Request Bool ChannelRequest
    | Data LBS.ByteString
    | EOF
    | Interrupt
    deriving Show

-- | Channel configuration that holds a function that handles
-- 'ChannelRequest's.
--
-- A sample 'ChannelConfig' can be found in 'defaultChannelConfig'.
data ChannelConfig =
    ChannelConfig
        { ccRequestHandler :: Bool -> ChannelRequest -> Channel ()
        }

-- | A sum that represents different possible channel requests.
data ChannelRequest
    = Shell                         -- ^ Spawn a shell.
    | Execute String                -- ^ Execute a command.
    | Subsystem String              -- ^ __TODO__ Document this
    | X11Forwarding
    | Environment String String
    | PseudoTerminal String Word32 Word32 Word32 Word32 String
    | WindowChange Word32 Word32 Word32 Word32
    | Signal String
    | ExitStatus Word32
    | ExitSignal String Bool String String
    | FlowControl Bool
    | Unknown String
    deriving Show

-- | A datatype that wraps the information returned from
-- 'runInteractiveCommand'.
data Process =
    Process
        { pHandle :: ProcessHandle
        , pIn :: Handle
        , pOut :: Handle
        , pError :: Handle
        }

instance Sender Channel where

    send :: SenderMessage -> Channel ()
    send m = gets csSend >>= liftIO . ($ m)

-- | Default 'ChannelConfig'.  Currently it only accepts 'Execute'
-- requests.
defaultChannelConfig :: ChannelConfig
defaultChannelConfig =
    ChannelConfig
        { ccRequestHandler = \wr req ->
            case req of
                Execute cmd -> do
                    spawnProcess (runInteractiveCommand cmd)
                    when wr channelSuccess
                _ -> do
                    channelError "accepting 'exec' requests only"
                    when wr channelFail
        }

newChannel :: ChannelConfig             -- ^ config for this channel
           -> (SenderMessage -> IO ())  -- ^ function for doing the sending
                                        -- on this channel.  See 'csSend'.
           -> Word32                    -- ^ our channel id.  See 'csID'.
           -> Word32                    -- ^ client's channel id.  See
                                        -- 'csTheirID'.
           -> Word32                    -- ^ Initial window size.  See
                                        -- 'csWindowSize'.
           -> Word32                    -- ^ Initial max packet size.  See
                                        -- 'csMaxPacket'.
           -> String                    -- ^ User name.  See 'csUser'.
           -> IO (Chan ChannelMessage)  -- A channel that we can send
                                        -- 'ChannelMessage's to.
newChannel config csend us them winSize maxPacket user = do
    chan <- newChan

    dump ("new channel", winSize, maxPacket)
    _ <- forkIO $ evalStateT (do
        -- This is an open channel confirmation message.  It is defined in
        -- <https://tools.ietf.org/html/rfc4254#section-5.1 rfc4254 section
        -- 5.1>.
        sendPacket $ do
            byte 91
            long them
            long us
            long (32768 * 64)
            long 32768

        chanLoop chan) $
        ChannelState
            { csConfig = config
            , csID = us
            , csTheirID = them
            , csSend = csend
            , csDataReceived = 0
            , csMaxPacket = maxPacket
            , csWindowSize = 32768 * 64
            , csTheirWindowSize = winSize
            , csUser = user
            , csProcess = Nothing
            , csRedirector = Nothing
            }

    return chan

-- | Loop over the 'Chan' and continuously read 'ChannelMessage'.  Act on
-- the 'ChannelMessage'.
--
-- Here is what will happen for each 'ChannelMessage':
--
--   ['Request'] Call the request handler in 'ccRequestHandler'.
--
--   ['Data'] Update 'csDataReceived' with the new data and adjust the
--   window size.
--
--   ['EOF'] Close the 'Process's stdin to indicate EOF.
--
--   ['Interrupt'] Close the redirecting process and the process.
chanLoop :: Chan ChannelMessage -> Channel ()
chanLoop c = do
    msg <- liftIO (readChan c)
    dump ("got channel message", msg)

    chanid <- gets csID
    case msg of
        Request wr cr -> do
            handler <- gets (ccRequestHandler . csConfig)
            handler wr cr

            chanLoop c

        -- This is described in
        -- <https://tools.ietf.org/html/rfc4254#section-5.2 rfc4254 section
        -- 5.2>.
        Data datum -> do
            modify $ \cs -> cs
                { csDataReceived =
                    csDataReceived cs + fromIntegral (LBS.length datum)
                }

            -- Adjust window size if needed
            rcvd <- gets csDataReceived
            maxp <- gets csMaxPacket
            winSize <- gets csTheirWindowSize
            when (rcvd + (maxp * 4) >= winSize && winSize + (maxp * 4) <= 2^(32 :: Integer) - 1) $ do
                modify $ \cs -> cs { csTheirWindowSize = winSize + (maxp * 4) }
                sendPacket $ do
                    byte 93
                    long chanid
                    long (maxp * 4)

            -- Direct input to process's stdin
            cproc <- gets csProcess
            case cproc of
                Nothing -> dump ("got unhandled data", chanid)
                Just (Process _ pin _ _) -> do
                    dump ("redirecting data", chanid, LBS.length datum)
                    liftIO $ LBS.hPut pin datum
                    liftIO $ hFlush pin

            chanLoop c

        EOF -> do
            modify $ \cs -> cs { csDataReceived = 0 }

            -- Close process's stdin to indicate EOF
            cproc <- gets csProcess
            case cproc of
                Nothing -> dump ("got unhandled eof")
                Just (Process _ pin _ _) -> do
                    dump ("redirecting eof", chanid)
                    liftIO $ hClose pin

            chanLoop c

        Interrupt -> do
            -- shut down the i/o redirecting process
            redir <- gets csRedirector
            case redir of
                Nothing -> return ()
                Just tid -> liftIO (killThread tid)

            cproc <- gets csProcess
            case cproc of
                Nothing -> return ()
                Just (Process phdl pin _ _) -> do
                    -- NOTE: this doesn't necessarily guarantee termination
                    -- see System.Process docs
                    -- nb closing stdin seems necessary, or process won't die
                    liftIO (hClose pin >> terminateProcess phdl)


-- | This sends a message to the client that represents the error data.
-- This is defined in <https://tools.ietf.org/html/rfc4254#section-5.2
-- rfc4254 section 5.2>.
channelError :: String -> Channel ()
channelError msg = do
    target <- gets csTheirID
    sendPacket $ do
        byte 95
        long target
        long 1
        string (msg ++ "\r\n")

-- | This sends data to the client.
-- Defined in <https://tools.ietf.org/html/rfc4254#section-5.2 rfc4254
-- section 5.2>.
channelMessage :: String -> Channel ()
channelMessage msg = do
    target <- gets csTheirID
    sendPacket $ do
        byte 94
        long target
        string (msg ++ "\r\n")

-- | Send a failure response to a channel specific request from a client.
-- Defined in <https://tools.ietf.org/html/rfc4254#section-5.4 rfc4254
-- section 5.4>.
channelFail :: Channel ()
channelFail = do
    target <- gets csTheirID
    sendPacket $ do
        byte 100
        long target

-- | Send a success response to a channel specific request from a client.
-- Defined in <https://tools.ietf.org/html/rfc4254#section-5.4 rfc4254
-- section 5.4>.
channelSuccess :: Channel ()
channelSuccess = do
    target <- gets csTheirID
    sendPacket $ do
        byte 99
        long target

-- | This sends the EOF and CLOSE messages to the client.
-- Defined in <https://tools.ietf.org/html/rfc4254#section-5.3 rfc4254
-- section 5.3>.
channelDone :: Channel ()
channelDone = do
    target <- gets csTheirID
    sendPacket (byte 96 >> long target) -- eof
    sendPacket (byte 97 >> long target) -- close

sendChunks :: Integral a => a -> Packet () -> String -> Channel ()
sendChunks _ _ "" = return ()
sendChunks n p s = do
    sendPacket (p >> string chunk)
    sendChunks n p rest
  where
    (chunk, rest) = splitAt (fromIntegral n - packetLength p) s

redirectHandle :: Chan () -> Packet () -> Handle -> Channel ()
redirectHandle f d h = do
    s <- get
    r <- liftIO . forkIO . evalStateT redirectLoop $ s
    modify $ \cs -> cs { csRedirector = Just r }
  where
    redirectLoop = do
        maxLen <- gets csMaxPacket

        dump "reading..."
        l <- liftIO $ getAvailable
        dump ("read data from handle", l)

        if not (null l)
            then sendChunks maxLen d l
            else return ()

        done <- liftIO $ hIsEOF h
        dump ("eof handle?", done)
        if done
            then liftIO $ writeChan f ()
            else redirectLoop

    getAvailable :: IO String
    getAvailable = do
        ready <- hReady h `Control.Exception.catch` (const (return False) :: IOException -> IO Bool)
        if not ready
            then return ""
            else do
                c <- hGetChar h
                cs <- getAvailable
                return (c:cs)

spawnProcess :: IO (Handle, Handle, Handle, ProcessHandle) -> Channel ()
spawnProcess cmd = do
    target <- gets csTheirID

    (pin, pout, perr, phdl) <- liftIO cmd
    modify (\s -> s { csProcess = Just $ Process phdl pin pout perr })

    dump ("command spawned")

    -- redirect stdout and stderr, using a channel to signal completion
    done <- liftIO newChan
    liftIO $ hSetBinaryMode pout True
    liftIO $ hSetBinaryMode perr True
    redirectHandle done (byte 94 >> long target) pout
    redirectHandle done (byte 95 >> long target >> long 1) perr

    s <- get

    -- spawn a thread to wait for the process to terminate
    void . liftIO . forkIO $ do
        -- wait until both are done
        readChan done
        readChan done

        dump "done reading output! waiting for process..."
        exit <- liftIO $ waitForProcess phdl
        dump ("process exited", exit)

        flip evalStateT s $ do
            sendPacket $ do
                byte 98
                long target
                string "exit-status"
                byte 0
                long (statusCode exit)

            channelDone
  where
    statusCode ExitSuccess = 0
    statusCode (ExitFailure n) = fromIntegral n

