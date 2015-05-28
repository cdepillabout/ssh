module SSH.NetReader where

import Control.Monad.Trans.State (State, gets, modify)
import Data.Binary (decode)
import Data.Int
import Data.Word
import qualified Data.ByteString.Lazy as LBS

import SSH.Packet
import SSH.Internal.Util (fromLBS)

-- Setup for the doctests.  Import additional modules.
-- $setup
-- >>> :m +Control.Monad.Trans.State
-- >>> :m +Data.Binary

-- | A 'NetReader' is just a 'State' 'Monad' with a state of an
-- 'LBS.ByteString'. In a @'State' s a@, the @s@ is the 'LBS.ByteString'
-- that is passed into the 'State' 'Monad'.  It's usually a large buffer in
-- memory that we are reading things out of (e.g. a byte with 'readByte',
-- an arbitrarily-sized 'Integer' with 'readInteger', etc).
--
-- 'NetReader' is kind of the opposite of 'Packet'.  'Packet' allows you to
-- create one big 'LBS.ByteString' out of many small things, whereas
-- 'NetReader' allows you to take one big 'LBS.ByteString' and break it
-- down to to many smaller types.
type NetReader = State LBS.ByteString


-- | Read one byte out of a larger 'LBS.ByteString'.
--
-- This is using 'LBS.head', so it fails when the state is an empty
-- 'LBS.ByteString'.
--
-- >>> flip runState "ABCDE" readByte
-- (65,"BCDE")
-- >>> flip runState "ABCDE" $ (,) <$> readByte <*> readByte
-- ((65,66),"CDE")
-- >>> flip runState "" readByte
-- (*** Exception: ...
--
readByte :: NetReader Word8
readByte = fmap LBS.head (readBytes 1)

-- | Read a 4 byte 'Int32' out of a larger 'LBS.ByteString'.
--
-- This is using 'LBS.head', so it fails when the state is an empty
-- 'LBS.ByteString'.
--
-- >>> let x = encode (4 :: Int32)
-- >>> flip runState x readLong
-- (4,"")
-- >>> let y = encode (0 :: Int32)
-- >>> flip evalState (x `LBS.append` y) $ (,) <$> readLong <*> readLong
-- (4,0)
-- >>> flip runState "" readLong
-- (*** Exception: ...
--
readLong :: NetReader Int32
readLong = fmap decode (readBytes 4)

readULong :: NetReader Word32
readULong = fmap decode (readBytes 4)

readInteger :: NetReader Integer
readInteger = do
    len <- readULong
    b <- readBytes (fromIntegral len)
    return (unmpint b)

-- |
readBytes :: Int -> NetReader LBS.ByteString
readBytes n = do
    p <- gets (LBS.take (fromIntegral n))
    modify (LBS.drop (fromIntegral n))
    return p

readLBS :: NetReader LBS.ByteString
readLBS = readULong >>= readBytes . fromIntegral

readString :: NetReader String
readString = fmap fromLBS readLBS

readBool :: NetReader Bool
readBool = fmap (== 1) readByte

