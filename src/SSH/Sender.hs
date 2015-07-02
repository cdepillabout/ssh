module SSH.Sender where

import Control.Concurrent.Chan (Chan, readChan)
import Control.Monad (replicateM)
import Data.Word (Word32, Word8)
import System.IO (Handle, hFlush)
import System.Random (randomRIO)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS

import SSH.Debug
import SSH.Crypto (Cipher(..), HMAC(..), encrypt)
import SSH.Packet (Packet, byte, doPacket, long, raw)

data SenderState
    = NoKeys
        { senderThem :: Handle
        , senderOutSeq :: Word32
        }
    | GotKeys
        { senderThem :: Handle
        , senderOutSeq :: Word32
        , senderEncrypting :: Bool
        , senderCipher :: Cipher
        , senderKey :: BS.ByteString
        , senderVector :: BS.ByteString
        , senderHMAC :: HMAC
        }

data SenderMessage
    = Prepare Cipher BS.ByteString BS.ByteString HMAC
    | StartEncrypting
    | Send LBS.ByteString
    | Stop

class Sender a where
    send :: SenderMessage -> a ()

    sendPacket :: Packet () -> a ()
    sendPacket = send . Send . doPacket

sender :: Chan SenderMessage -> SenderState -> IO ()
sender senderMessageChan senderState = do
    m <- readChan senderMessageChan
    case m of
        Stop -> return ()
        Prepare cipher key iv hmac -> do
            dump ("initiating encryption", key, iv)
            let gotKeys = GotKeys { senderThem = senderThem senderState
                                  , senderOutSeq = senderOutSeq senderState
                                  , senderEncrypting = False
                                  , senderCipher = cipher
                                  , senderKey = key
                                  , senderVector = iv
                                  , senderHMAC = hmac
                                  }
            sender senderMessageChan gotKeys
        StartEncrypting -> do
            dump ("starting encryption")
            let encryptingSenderState = senderState { senderEncrypting = True }
            sender senderMessageChan encryptingSenderState
        Send msg -> do
            let paddingLength = fromIntegral $ paddingLen msg
                rand = randomRIO (0, 255 :: Int)
            intPad <- replicateM paddingLength rand
            let pad = LBS.pack . map fromIntegral $ intPad
            let f = full msg pad
            case senderState of
                GotKeys h os True cipher key iv (HMAC _ mac) -> do
                    dump ("sending encrypted", os, f)
                    let (encrypted, newVector) = encrypt cipher key iv f
                    LBS.hPut h . LBS.concat $
                        [ encrypted
                        , mac . doPacket $ long os >> raw f
                        ]
                    hFlush h
                    sender senderMessageChan $ senderState
                        { senderOutSeq = senderOutSeq senderState + 1
                        , senderVector = newVector
                        }
                _ -> do
                    dump ("sending unencrypted", senderOutSeq senderState, f)
                    LBS.hPut (senderThem senderState) f
                    hFlush (senderThem senderState)
                    sender senderMessageChan (senderState { senderOutSeq = senderOutSeq senderState + 1 })
  where
    blockSize =
        case senderState of
            GotKeys { senderCipher = Cipher _ _ bs _ }
                | bs > 8 -> bs
            _ -> 8

    -- | Turns a message and a pad into a packet with 'doPacket'.
    --
    -- Four things will be in the the resulting 'LBS.ByteString'.
    --  1. a 'long' of the message's length calculated with 'len'.
    --  2. a 'byte' of the padding length calculated with 'paddingLen'.
    --  2. a 'raw' of the message.
    --  2. a 'raw' of the pad.
    full :: LBS.ByteString -- ^ message to pad and turn into a packet
         -> LBS.ByteString -- ^ padding
         -> LBS.ByteString
    full msg pad = doPacket $ do
        long (len msg)
        byte (paddingLen msg)
        raw msg
        raw pad

    -- | Calculate the message length.  Used in 'full' above.
    --
    -- The calculation is 1 plus the length of the message plus the length
    -- of the padding returned from 'paddingLen'.
    len :: LBS.ByteString -> Word32
    len msg = 1 + fromIntegral (LBS.length msg) + fromIntegral (paddingLen msg)

    paddingNeeded :: LBS.ByteString -> Word8
    paddingNeeded msg = fromIntegral blockSize - (fromIntegral $ (5 + LBS.length msg) `mod` fromIntegral blockSize)

    paddingLen :: LBS.ByteString -> Word8
    paddingLen msg =
        if paddingNeeded msg < 4
            then paddingNeeded msg + fromIntegral blockSize
            else paddingNeeded msg
