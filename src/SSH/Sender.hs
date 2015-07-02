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
            let paddingLength = fromIntegral $ paddingLen msg senderState
                rand = randomRIO (0, 255 :: Int)
            intPad <- replicateM paddingLength rand
            let pad = LBS.pack . map fromIntegral $ intPad
            let f = full msg pad senderState
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
    -- | Return blocksize needed for a message in 'SenderState'.  If we are
    -- in the state of 'GotKeys', then if the blocksize of the
    -- 'senderCipher' is more than 8, we use it, otherwise we just use 8.
    blockSize :: SenderState -> Int
    blockSize senderState' =
        case senderState' of
            GotKeys { senderCipher = Cipher _ _ bs _ }
                | bs > 8 -> bs
            _ -> 8

    -- | Turns a message and a pad into a packet with 'doPacket'.
    --
    -- Four things will be in the the resulting 'LBS.ByteString'.
    --   1. a 'long' of the message's length calculated with 'len'.
    --   2. a 'byte' of the padding length calculated with 'paddingLen'.
    --   3. a 'raw' of the message.
    --   4. a 'raw' of the pad.
    --
    -- This is defined in <http://tools.ietf.org/html/rfc4253#section-6
    -- rfc4253, section 6>.
    full :: LBS.ByteString -- ^ message to pad and turn into a packet
         -> LBS.ByteString -- ^ padding
         -> SenderState    -- ^ current 'SenderState' ('GotKeys' messages have
                           -- a different blocksize.
         -> LBS.ByteString
    full msg pad senderState' = doPacket $ do
        long (len msg senderState')
        byte (paddingLen msg senderState')
        raw msg
        raw pad

    -- | Calculate the packet length.  Used in 'full' above.
    --
    -- The calculation is 1 (for the padding_length field) plus the length
    -- of the message (the payload) plus the length of the padding returned from
    -- 'paddingLen' (the random padding field).
    --
    -- This is defined in <http://tools.ietf.org/html/rfc4253#section-6
    -- rfc4253, section 6>.  The packet_len field is the length of the
    -- packet, not including the 'mac' or 'packet_length' field itself.
    len :: LBS.ByteString -> SenderState -> Word32
    len msg senderState' =
        let messageLength = fromIntegral $ LBS.length msg
            paddingLength = fromIntegral $ paddingLen msg senderState'
        -- The 1 is being added because it represents 1 byte for the
        -- padding_length field.
        in 1 + messageLength + paddingLength

    -- | Calculate the amount of padding needed based on the message
    -- length and current 'SenderState'.
    paddingNeeded :: LBS.ByteString -> SenderState -> Word8
    paddingNeeded msg senderState' =
        let blockSize' = blockSize senderState'
            -- We are adding 5 here because it is the length of the
            -- packet_length field (4 bytes) plus the padding_length field
            -- (1 byte).
            messageLength = 5 + LBS.length msg
            moddedMessage = messageLength `mod` fromIntegral blockSize'
        in fromIntegral blockSize' - fromIntegral moddedMessage

    -- | Calculate the padding length needed for a given message based on
    -- the message length and the 'SenderState'.  We use 'paddingNeeded'
    -- here.  If 'paddingNeeded' returns a number less than 4, then we
    -- return that numer plus the 'blockSize'.  Otherwise, we just return
    -- the value from 'paddingNeeded'.
    --
    -- This is defined in <http://tools.ietf.org/html/rfc4253#section-6
    -- rfc4253, section 6>.  It says, "There MUST be at least four
    -- bytes of padding.  The padding SHOULD consist of random bytes.  The
    -- maximum amount of padding is 255 bytes."
    paddingLen :: LBS.ByteString -> SenderState -> Word8
    paddingLen msg senderState' =
        let paddingNeeded' = paddingNeeded msg senderState'
            blockSize' = fromIntegral $ blockSize senderState'
        in if paddingNeeded' < 4
            then paddingNeeded' + blockSize'
            else paddingNeeded'
