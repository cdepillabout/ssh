module SSH.Packet where

import Control.Monad.Trans.Writer (Writer, execWriter, tell)
import Data.Binary (encode)
import Data.Bits ((.&.))
import Data.Digest.Pure.SHA
import Data.Word (Word8, Word32)
import qualified Data.ByteString.Lazy as LBS

import SSH.Internal.Util

-- | A convenience wrapper around a 'Writer' holding a 'LBS.ByteString'.
--
-- See the note about the similarity with @NetReader@ at the 'NetReader'
-- haddock.
type Packet a = Writer LBS.ByteString a

-- | Run 'doPacket' and return the length of the inner 'LBS.ByteString'.
--
-- >>> packetLength $ byte 1 >> byte 10 >> byte 33
-- 3
-- >>> packetLength $ return ()
-- 0
packetLength :: Packet () -> Int
packetLength = fromIntegral . LBS.length . doPacket

-- | Small wrapper around 'execWriter'.  Return the packet that has been
-- builtup.
doPacket :: Packet a -> LBS.ByteString
doPacket = execWriter

-- | Encode a 'Word8' with 'Data.Binary.encode' and put in the 'Packet'.
--
-- >>> SSH.Debug.showHexLazyByteString . doPacket $ byte 65 >> byte 66 >> byte 67
-- ["41","42","43"]
-- >>> SSH.Debug.showHexLazyByteString . doPacket $ byte (-1)
-- ["ff"]
byte :: Word8 -> Packet ()
byte = tell . encode

-- | Encode a 'Word32' with 'Data.Binary.encode' and put in the 'Packet'.
--
-- >>> SSH.Debug.showHexLazyByteString . doPacket $ long 0
-- ["0","0","0","0"]
-- >>> SSH.Debug.showHexLazyByteString . doPacket $ long $ 65 * 256 + 66
-- ["0","0","41","42"]
-- >>> SSH.Debug.showHexLazyByteString . doPacket $ long (-1)
-- ["ff","ff","ff","ff"]
long :: Word32 -> Packet ()
long = tell . encode

-- | Encode an 'Integer with 'mpint' and put in the 'Packet'.
--
-- >>> SSH.Debug.showHexLazyByteString . doPacket $ integer 3
-- ["0","0","0","1","3"]
integer :: Integer -> Packet ()
integer = tell . mpint

-- | Encode a 'LBS.ByteString' with 'netLBS' and put in the 'Packet'.
byteString :: LBS.ByteString -> Packet ()
byteString = tell . netLBS

-- | Convert a 'String' to a 'LBS.ByteString', and then pass it to
-- 'byteString'.
--
-- >>> SSH.Debug.showHexLazyByteString . doPacket $ string "abcde"
-- ["0","0","0","5","61","62","63","64","65"]
-- >>> SSH.Debug.showHexLazyByteString . doPacket $ string ""
-- ["0","0","0","0"]
string :: String -> Packet ()
string = byteString . toLBS

-- | Put a raw 'LBS.ByteString' in a 'Packet'.  This is like 'byteString',
-- but it does not pass the 'LBS.ByteString' to 'netLBS' first.
raw :: LBS.ByteString -> Packet ()
raw = tell

-- | Like 'raw', but for 'String's.  'string' is to 'byteString' like 'raw'
-- is to 'rawString'.
--
-- >>> SSH.Debug.showHexLazyByteString . doPacket $ rawString "abcde"
-- ["61","62","63","64","65"]
-- >>> SSH.Debug.showHexLazyByteString . doPacket $ rawString ""
-- []
rawString :: String -> Packet ()
rawString = tell . toLBS

-- | Convert a string to a 'LBS.ByteString' and the pass it to 'netLBS'.
--
-- >>> SSH.Debug.showHexLazyByteString $ netString "abcde"
-- ["0","0","0","5","61","62","63","64","65"]
-- >>> SSH.Debug.showHexLazyByteString $ netString ""
-- ["0","0","0","0"]
netString :: String -> LBS.ByteString
netString = netLBS . toLBS

-- | Prepend a 'Word32' representing the size of a 'LBS.ByteString' to the
-- front of it.
--
-- >>> SSH.Debug.showHexLazyByteString . netLBS $ Data.ByteString.Lazy.Char8.pack ""
-- ["0","0","0","0"]
-- >>> SSH.Debug.showHexLazyByteString . netLBS $ Data.ByteString.Lazy.Char8.pack "a"
-- ["0","0","0","1","61"]
-- >>> SSH.Debug.showHexLazyByteString . netLBS $ Data.ByteString.Lazy.Char8.pack "abcd"
-- ["0","0","0","4","61","62","63","64"]
netLBS :: LBS.ByteString -> LBS.ByteString
netLBS bs = encode (fromIntegral (LBS.length bs) :: Word32) `LBS.append` bs

-- | Convert an arbitrarily large 'Integer' to a 'LBS.ByteString'.
--
-- This works by using 'i2osp' to convert an 'Integer' to an octet list,
-- and then using 'netLBS' to add the length of the 'Integer' on to the
-- front of it.
--
-- This has some funny logic where if the most significant bit of the octet
-- list is greater than 127, it adds an additional 0 byte to the front of
-- the octet list.  You can see it in the examples below with 127 and 128.
--
-- >>> SSH.Debug.showHexLazyByteString $ mpint 1
-- ["0","0","0","1","1"]
-- >>> SSH.Debug.showHexLazyByteString $ mpint 15
-- ["0","0","0","1","f"]
-- >>> SSH.Debug.showHexLazyByteString $ mpint 127
-- ["0","0","0","1","7f"]
-- >>> SSH.Debug.showHexLazyByteString $ mpint 128
-- ["0","0","0","2","0","80"]
--
-- __WARNING__: This throws an error if the 'Integer' is 0, and it runs
-- forever if it is less than 0.
mpint :: Integer -> LBS.ByteString
mpint i = netLBS (if LBS.head enc .&. 128 > 0
                      then 0 `LBS.cons` enc
                      else enc)
  where
    enc :: LBS.ByteString
    enc = LBS.pack (i2osp 0 i)

-- | Despite what it's name looks like, this is NOT the opposite of
-- 'mpint'.  It doesn't undo what netLBS does.  Take a look at the
-- following examples to get a feeling for how to use it.
--
-- >>> unmpint . LBS.drop 4 $ mpint 1
-- 1
-- >>> unmpint . LBS.drop 4 $ mpint 918112219
-- 918112219
unmpint :: LBS.ByteString -> Integer
unmpint = fromOctets (256 :: Integer) . LBS.unpack

-- warning: don't try to send this; it's an infinite bytestring.
-- take whatever length the key needs.
-- TODO: write the documentation and tests for this.
makeKey :: Integer -> LBS.ByteString -> Char -> LBS.ByteString
makeKey s h c = makeKey' initial
  where
    initial = bytestringDigest . sha1 . LBS.concat $
        [ mpint s
        , h
        , LBS.singleton . fromIntegral . fromEnum $ c
        , h
        ]

    makeKey' acc = LBS.concat
        [ acc
        , makeKey' (bytestringDigest . sha1 . LBS.concat $ [mpint s, h, acc])
        ]

