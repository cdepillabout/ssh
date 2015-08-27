{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}

module SSH.Server.Loop where

import Control.Concurrent.Lifted (fork)
import Control.Concurrent.Chan (newChan, writeChan)
import Control.Monad (replicateM, void)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Control.Monad.Trans.Control (MonadBaseControl)
import Control.Monad.Trans.State (evalStateT, get, gets, modify)
import qualified Data.ByteString.Lazy as LBS
import Data.Digest.Pure.SHA (bytestringDigest, sha1)
import qualified Data.Map as M
import Data.List (intercalate)
import Data.List.Split (splitOn)
import Data.Word (Word8)
import Network (HostName, PortNumber, Socket, accept)
import OpenSSL.BN (randIntegerOneToNMinusOne, modexp)
import System.IO (Handle, hFlush, hGetLine, hIsEOF, hPutStr, hSetBinaryMode)
import System.Random (randomRIO)

import SSH.Channel
import SSH.Crypto
import SSH.Debug
import SSH.NetReader
import SSH.Packet
import SSH.Sender
import SSH.Session
import SSH.Supported
import SSH.Internal.Util

waitLoop :: (MonadIO m, MonadBaseControl IO m)
         => SessionConfig
         -> ChannelConfig
         -> Socket
         -> m ()
waitLoop sessionConf channelConf socket = do
    (handle, hostName, port) <- acceptBinaryMode socket
    dump ("got connection from", hostName, port)
    void . fork $ handleConnection sessionConf channelConf handle
    waitLoop sessionConf channelConf socket

-- | Call 'accept' and set the resulting 'Handle's binary mode to 'True'
-- using 'hSetBinaryMode'.
acceptBinaryMode :: (MonadIO m) => Socket -> m (Handle, HostName, PortNumber)
acceptBinaryMode socket = do
    (handle, hostName, port) <- liftIO $ accept socket
    liftIO $ hSetBinaryMode handle True
    return (handle, hostName, port)

-- | Print the ssh 'version' to a 'Handle'.
sendSSHVersion :: (MonadIO m) => Handle -> m ()
sendSSHVersion handle = do
    liftIO $ hPutStr handle (version ++ "\r\n")
    liftIO $ hFlush handle

-- | Read in the client's ssh version from a 'Handle'.
getSSHVersion :: (MonadIO m) => Handle -> m String
getSSHVersion handle = do
    versionLine <- liftIO $ hGetLine handle
    return $ takeWhile (/= '\r') versionLine

-- | Create a cookie for the key exechange.
createCookie :: (MonadIO m) => m LBS.ByteString
createCookie = do
    randomWord8s <- replicateM 16 $ liftIO $ randomRIO (0, 255 :: Word8)
    return $ LBS.pack randomWord8s

handleConnection :: (MonadIO m, MonadBaseControl IO m)
      => SessionConfig
      -> ChannelConfig
      -> Handle
      -> m ()
handleConnection sessionConf channelConf handle = do
    -- send SSH server version
    sendSSHVersion handle
    -- checking for done here seems kind of weird?
    done <- liftIO $ hIsEOF handle
    if done
        then return ()
        else do
            -- get the version response
            theirVersion <- getSSHVersion handle
            cookie <- createCookie
            let ourKEXInit = doPacket $ pKEXInit cookie

            out <- liftIO newChan
            _ <- fork (liftIO . sender out $ NoKeys handle 0)

            liftIO $ evalStateT
                (send (Send ourKEXInit) >> readLoop)
                (Initial
                    { ssConfig = sessionConf
                    , ssChannelConfig = channelConf
                    , ssThem = handle
                    , ssSend = writeChan out
                    , ssPayload = LBS.empty
                    , ssTheirVersion = theirVersion
                    , ssOurKEXInit = ourKEXInit
                    , ssInSeq = 0
                    })
  where
    -- | This is defined in
    -- <https://tools.ietf.org/html/rfc4253#section-7.1 rfc4253 section
    -- 7.1>.
    pKEXInit :: LBS.ByteString -> Packet ()
    pKEXInit cookie = do
        byte 20

        raw cookie

        mapM_ string
            [ intercalate "," $ supportedKeyExchanges
            , intercalate "," $ supportedKeyAlgorithms
            , intercalate "," $ map fst supportedCiphers
            , intercalate "," $ map fst supportedCiphers
            , intercalate "," $ map fst supportedMACs
            , intercalate "," $ map fst supportedMACs
            , supportedCompression
            , supportedCompression
            , supportedLanguages
            , supportedLanguages
            ]

        byte 0 -- first_kex_packet_follows (boolean)
        long 0

readLoop :: Session ()
readLoop = do
    done <- gets ssThem >>= liftIO . hIsEOF
    if done
        then shutdownChannels
        else do

            getPacket

            msg <- net readByte

            if msg == 1 || msg == 97 -- disconnect || close
                then shutdownChannels
                else do

                    -- The following message id values are defined in
                    -- <https://tools.ietf.org/html/rfc4250#section-4.1.2
                    -- rfc4250 section 4.1.2>.
                    case msg of
                        -- transportation layer messages
                        5 -> serviceRequest
                        20 -> kexInit
                        21 -> newKeys
                        -- ...?
                        30 -> kexDHInit
                        -- user authentication layer messages
                        50 -> userAuthRequest
                        -- connection layer messages
                        90 -> channelOpen
                        94 -> dataReceived
                        96 -> eofReceived
                        98 -> channelRequest
                        u -> dump $ "unknown message: " ++ show u

                    modify (\s -> s { ssInSeq = ssInSeq s + 1 })
                    readLoop
  where
    shutdownChannels = do
        s <- get
        case s of
            Final { ssChannels = cs } ->
                mapM_ (liftIO . flip writeChan Interrupt) (M.elems cs)
            _ -> return ()

        liftIO $ ssSend s Stop

-- | Start doing the actual key exchange initialization.
-- Defined in <http://tools.ietf.org/html/rfc4253#section-7.1 rfc4253
-- section 7.1>.
--
-- We can also do key re-exchanges like in
-- <http://tools.ietf.org/html/rfc4253#section-9 rfc4253 section 9>.
--
-- TODO: Key exchanges should be happening after we exchange a gigabyte of
-- data or after an hour, whichever comes sooner.
kexInit :: Session ()
kexInit = do
    cookie <- net (readBytes 16)
    nameLists <- fmap (map (splitOn "," . fromLBS)) (replicateM 10 (net readLBS))
    kpf <- net readByte
    dummy <- net readULong

    let theirKEXInit = reconstruct cookie nameLists kpf dummy
        ocn = match (nameLists !! 3) (map fst supportedCiphers)
        icn = match (nameLists !! 2) (map fst supportedCiphers)
        omn = match (nameLists !! 5) (map fst supportedMACs)
        imn = match (nameLists !! 4) (map fst supportedMACs)

    dump ("KEXINIT", theirKEXInit, ocn, icn, omn, imn)
    modify $ \st ->
        case st of
            Initial c channelConf h s p cv sk is ->
                case
                    ( lookup ocn supportedCiphers
                    , lookup icn supportedCiphers
                    , lookup omn supportedMACs
                    , lookup imn supportedMACs
                    ) of
                    (Just oc, Just ic, Just om, Just im) ->
                        GotKEXInit
                            { ssConfig = c
                            , ssChannelConfig = channelConf
                            , ssThem = h
                            , ssSend = s
                            , ssPayload = p
                            , ssTheirVersion = cv
                            , ssOurKEXInit = sk
                            , ssTheirKEXInit = theirKEXInit
                            , ssOutCipher = oc
                            , ssInCipher = ic
                            , ssOutHMACPrep = om
                            , ssInHMACPrep = im
                            , ssInSeq = is
                            }
                    _ ->
                        error . concat $
                            [ "impossible: lookup failed for ciphers/macs: "
                            , show (ocn, icn, omn, imn)
                            ]
            _ -> error "impossible state transition; expected Initial"
  where
    match :: Eq a => [a] -> [a] -> a
    match n h = head . filter (`elem` h) $ n

    reconstruct c nls kpf dummy = doPacket $ do
        byte 20
        raw c
        mapM_ (string . intercalate ",") nls
        byte kpf
        long dummy

-- | This is described in <http://tools.ietf.org/html/rfc4253#section-7.1
-- rfc4253 section 7> and <https://tools.ietf.org/html/rfc4253#section-8
-- rfc4253 section 8>.
kexDHInit :: Session ()
kexDHInit = do
    e <- net readInteger -- other party's public number
    dump ("KEXDH_INIT", e)

   -- our private number
    y <- liftIO $ randIntegerOneToNMinusOne ((safePrime - 1) `div` 2) -- q?

    let f = modexp generator y safePrime
        k = modexp e y safePrime

    keyPair <- gets (scKeyPair . ssConfig)

    let pub =
            case keyPair of
                RSAKeyPair { rprivPub = p } -> p
                DSAKeyPair { dprivPub = p } -> p
    d <- digest e f k pub

    let [civ, siv, ckey, skey, cinteg, sinteg] = map (makeKey k d) ['A'..'F']
    dump ("DECRYPT KEY/IV", LBS.take 16 ckey, LBS.take 16 civ)

    oc <- gets ssOutCipher
    om <- gets ssOutHMACPrep
    send $
        Prepare
            oc
            (strictLBS $ LBS.take (fromIntegral $ cKeySize oc) $ skey)
            (strictLBS $ LBS.take (fromIntegral $ cBlockSize oc) $ siv)
            (om sinteg)

    modify $ \st ->
        case st of
            GotKEXInit c channelConf h s p _ _ is _ _ ic _ im ->
                Final
                    { ssConfig = c
                    , ssChannelConfig = channelConf
                    , ssChannels = M.empty
                    , ssID = d
                    , ssThem = h
                    , ssSend = s
                    , ssPayload = p
                    , ssGotNEWKEYS = False
                    , ssInSeq = is
                    , ssInCipher = ic
                    , ssInHMAC = im cinteg
                    , ssInKey =
                        strictLBS $ LBS.take (fromIntegral $ cKeySize ic) $ ckey
                    , ssInVector =
                        strictLBS $ LBS.take (fromIntegral $ cBlockSize ic) $ civ
                    , ssUser = Nothing
                    }

            _ -> error "impossible state transition; expected GotKEXInit"



    signed <- liftIO $ sign keyPair d
    let reply = doPacket (kexDHReply f signed pub)
    dump ("KEXDH_REPLY", reply)

    send (Send reply)
  where
    kexDHReply f s p = do
        byte 31
        byteString (blob p)
        integer f
        byteString s

    digest e f k p = do
        cv <- gets ssTheirVersion
        ck <- gets ssTheirKEXInit
        sk <- gets ssOurKEXInit
        return . bytestringDigest . sha1 . doPacket $ do
            string cv
            string version
            byteString ck
            byteString sk
            byteString (blob p)
            integer e
            integer f
            integer k

newKeys :: Session ()
newKeys = do
    sendPacket (byte 21)
    send StartEncrypting
    modify (\ss -> ss { ssGotNEWKEYS = True })

serviceRequest :: Session ()
serviceRequest = do
    name <- net readLBS
    sendPacket $ do
        byte 6
        byteString name

-- |
--
-- This is described in <https://tools.ietf.org/html/rfc4252#section-5
-- rfc4252 section 5>.
--
-- TODO: Take a good look at this.  It seems fishy.
userAuthRequest :: Session ()
userAuthRequest = do
    user <- net readLBS
    service <- net readLBS
    method <- net readLBS

    auth <- gets (scAuthorize . ssConfig)
    authMethods <- gets (scAuthMethods . ssConfig)

    dump ("userauth attempt", user, service, method)

    let
        authorized = do
            sendPacket userAuthOK
            modify (\s -> s { ssUser = Just (fromLBS user) })

        authfailed = sendPacket $ userAuthFail authMethods

    case fromLBS method of
        x | x `notElem` authMethods -> authfailed

        -- The "publickey" auth method is defined in
        -- <https://tools.ietf.org/html/rfc4252#section-7 rfc4252 section
        -- 7>.
        "publickey" -> do
            b <- net readByte
            name <- net readLBS
            key <- net readLBS

            let pkey = blobToKey key
            ch <- auth (PublicKey (fromLBS user) pkey)

            case (ch, b == 1) of
              (False, _) -> authfailed
              (True, True) ->
                  do sig <- net readLBS
                     sessionID <- gets ssID
                     let message =
                           doPacket $ do
                               byteString sessionID
                               byte 50 -- SSH_MSG_USERAUTH_REQUEST
                               byteString user
                               byteString service
                               string "publickey"
                               byte 1 -- TRUE
                               byteString name
                               byteString key
                     ok <- liftIO $ verify pkey message sig
                     if ok then authorized else authfailed
              (True, False) -> sendPacket $ userAuthPKOK name key

        -- The "password" method is described in
        -- <https://tools.ietf.org/html/rfc4252#section-8 rfc4252 section
        -- 8>.
        "password" -> do
            0 <- net readByte
            password <- net readLBS
            ch <- auth (Password (fromLBS user) (fromLBS password))
            if ch then authorized else authfailed

        u -> error $ "unhandled authorization type: " ++ u

  where

    -- | Send SSH_MSG_USERAUTH_FAILURE and the list of authentication
    -- methods that can continue.
    --
    -- This is described in
    -- <https://tools.ietf.org/html/rfc4252#section-5.1 rfc4252 section
    -- 5.1>.
    userAuthFail :: [String] -> Packet ()
    userAuthFail ms = do
        byte 51
        string (intercalate "," ms)
        byte 0

    userAuthPKOK :: LBS.ByteString -> LBS.ByteString -> Packet ()
    userAuthPKOK name key = do
        byte 60
        byteString name
        byteString key

    -- | This just sends a SSH_MSG_USERAUTH_SUCCESS.
    --
    -- This is described in
    -- <https://tools.ietf.org/html/rfc4252#section-5.1 rfc4252 section
    -- 5.1>.
    userAuthOK :: Packet ()
    userAuthOK = byte 52

-- | Defined in <https://tools.ietf.org/html/rfc4254#section-6.1 rfc4254
-- section 6.1>.
channelOpen :: Session ()
channelOpen = do
    name <- net readLBS
    them <- net readULong
    windowSize <- net readULong
    maxPacketLength <- net readULong

    dump ("channel open", name, them, windowSize, maxPacketLength)

    us <- newChannelID

    chan <- do
        c <- gets ssChannelConfig
        s <- gets ssSend
        Just u <- gets ssUser
        liftIO $ newChannel c s us them windowSize maxPacketLength u

    modify (\s -> s
        { ssChannels = M.insert us chan (ssChannels s) })

-- | Defined in <https://tools.ietf.org/html/rfc4254#section-6 rfc4254
-- section 6>.
channelRequest :: Session ()
channelRequest = do
    chan <- net readULong >>= getChannel
    typ <- net readLBS
    wantReply <- net readBool

    let sendRequest = liftIO . writeChan chan . Request wantReply

    case fromLBS typ of
        "pty-req" -> do
            term <- net readString
            [cols, rows, width, height] <- replicateM 4 $ net readULong
            modes <- net readString
            sendRequest (PseudoTerminal term cols rows width height modes)

        "x11-req" -> sendRequest X11Forwarding

        "shell" -> sendRequest Shell

        "exec" -> do
            command <- net readString
            dump ("execute command", command)
            sendRequest (Execute command)

        "subsystem" -> do
            name <- net readString
            dump ("subsystem request", name)
            sendRequest (Subsystem name)

        "env" -> do
            name <- net readString
            value <- net readString
            dump ("environment request", name, value)
            sendRequest (Environment name value)

        "window-change" -> do
            cols <- net readULong
            rows <- net readULong
            width <- net readULong
            height <- net readULong
            sendRequest (WindowChange cols rows width height)

        "xon-xoff" -> do
            b <- net readBool
            sendRequest (FlowControl b)

        "signal" -> do
            name <- net readString
            sendRequest (Signal name)

        "exit-status" -> do
            status <- net readULong
            sendRequest (ExitStatus status)

        "exit-signal" -> do
            name <- net readString
            dumped <- net readBool
            msg <- net readString
            lang <- net readString
            sendRequest (ExitSignal name dumped msg lang)

        u -> sendRequest (Unknown u)

    dump ("request processed")

-- | Defined in <https://tools.ietf.org/html/rfc4254#section-6.6 rfc4254
-- section 6.6>.
dataReceived :: Session ()
dataReceived = do
    dump "got data"
    chan <- net readULong >>= getChannel
    msg <- net readLBS
    liftIO $ writeChan chan (Data msg)
    dump "data processed"


eofReceived :: Session ()
eofReceived = do
    chan <- net readULong >>= getChannel
    liftIO $ writeChan chan EOF
