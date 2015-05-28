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
-- >>> :set -XScopedTypeVariables
-- >>> import Control.Monad.Trans.State
-- >>> import Data.Binary
-- >>> import SSH.Internal.Util (toLBS)

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
-- >>> runState readByte "ABCDE"
-- (65,"BCDE")
-- >>> flip runState "ABCDE" $ (,) <$> readByte <*> readByte
-- ((65,66),"CDE")
-- >>> runState readByte ""
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
-- >>> runState readLong x
-- (4,"")
-- >>> let y = encode (0 :: Int32)
-- >>> flip evalState (x `LBS.append` y) $ (,) <$> readLong <*> readLong
-- (4,0)
-- >>> runState readLong ""
-- (*** Exception: ...
--
readLong :: NetReader Int32
readLong = fmap decode (readBytes 4)

-- | Read a 4 byte 'Word32' out of a larger 'LBS.ByteString'.  Similar to
-- 'readLong'
readULong :: NetReader Word32
readULong = fmap decode (readBytes 4)

-- | Read an arbitrarily long 'Integer' out of a larger 'LBS.ByteString'.
-- First reads 4 bytes for the length of the 'Integer' with 'readULong'.
-- Then uses 'readBytes' to read the remaining octets.  Pass the value to
-- 'unmpint'.
--
-- Throws an exception if it tries to read an 'Integer' with an incorrect
-- length value prepended to it.
--
-- >>> evalState readInteger (mpint 10)
-- 10
-- >>> evalState readInteger (mpint 128)
-- 128
-- >>> evalState readInteger ""
-- *** Exception: ...
--
readInteger :: NetReader Integer
readInteger = do
    len <- readULong
    b <- readBytes (fromIntegral len)
    return (unmpint b)

-- | Return the first 'Int' bytes of the 'NetReader' as a 'LBS.ByteString'.
--
-- >>> flip runState "ABCDE" $ readBytes 2
-- ("AB","CDE")
-- >>> flip runState "ABCDE" $ readBytes 10
-- ("ABCDE","")
-- >>> flip runState "ABCDE" $ readBytes 0
-- ("","ABCDE")
-- >>> flip runState "ABCDE" $ readBytes (-5)
-- ("","ABCDE")
-- >>> flip runState "" $ readBytes 100
-- ("","")
--
readBytes :: Int -> NetReader LBS.ByteString
readBytes n = do
    p <- gets (LBS.take (fromIntegral n))
    modify (LBS.drop (fromIntegral n))
    return p

-- | Read a 'LBS.ByteString' that has it's length on the front of it.
--
-- >>> evalState readLBS $ netLBS "hello"
-- "hello"
--
-- prop> \(str::String) -> evalState readLBS (netLBS $ toLBS str) == toLBS str
--
readLBS :: NetReader LBS.ByteString
readLBS = do
    len <- readULong
    readBytes $ fromIntegral len

-- | Calls 'fromLBS' on result from 'readLBS'.
readString :: NetReader String
readString = fmap fromLBS readLBS

-- | Returns 'True' if byte read with 'readByte' is equal to 1.  Otherwise,
-- returns 'False'.
--
-- >>> evalState readBool "\001"
-- True
-- >>> evalState readBool "\NUL"
-- False
-- >>> evalState readBool "a"
-- False
--
readBool :: NetReader Bool
readBool = fmap (== 1) readByte
