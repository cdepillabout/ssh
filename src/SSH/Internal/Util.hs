{-# LANGUAGE MagicHash #-}
module SSH.Internal.Util where

import Data.Word (Word8)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS

import GHC.Base (Int(I#))
import GHC.Integer.Logarithms (integerLog2#)


-- | Convert a 'String' to a lazy 'Data.ByteString.Lazy.ByteString'.
toLBS :: String -> LBS.ByteString
toLBS = LBS.pack . map (fromIntegral . fromEnum)

-- | Convert a lazy 'Data.ByteString.Lazy.ByteString' to a 'String'.
fromLBS :: LBS.ByteString -> String
fromLBS = map (toEnum . fromIntegral) . LBS.unpack

-- | Convert a lazy 'Data.ByteString.Lazy.ByteString' to a strict
-- 'Data.ByteString.ByteString'.
strictLBS :: LBS.ByteString -> BS.ByteString
strictLBS = BS.concat . LBS.toChunks

-- | Generate a infinite list that contains the powers of a number.
--
-- >>> take 6 $ powersOf 3
-- [1, 3, 9, 27, 81, 216]
powersOf :: Num a => a -> [a]
powersOf n = 1 : map (*n) (powersOf n)

-- | Converts a number into a different base, and returns it as
-- a list of decimal numbers.
--
-- >>> toBase 2 7
-- [1,1,1]
-- >>> toBase 2 14
-- [1,1,1,0]
-- >>> toBase 10 30
-- [3,0]
-- >>> toBase 50 40
-- [40]
--
-- *TODO* This shouldn't accept a number less than 2 as the first argument.
-- It should not accept a negative number as the second argument.
toBase :: (Integral a, Num b) => a    -- ^ base to use
                              -> a    -- ^ number to convert
                              -> [b]
toBase x =
    map fromIntegral .
        reverse .
        map (`mod` x) .
        takeWhile (/= 0) .
        iterate (`div` x)

toOctets :: (Integral a, Integral b) => a -> b -> [Word8]
toOctets n = toBase n . fromIntegral

fromOctets :: (Integral a, Integral b) => a -> [Word8] -> b
fromOctets n x =
    fromIntegral $ sum $
        zipWith (*) (powersOf n) (reverse (map fromIntegral x))

i2osp :: Integral a => Int -> a -> [Word8]
i2osp l y =
   pad ++ z
      where
         pad = replicate (l - unPaddedLen) (0x00::Word8)
         z = toOctets (256 :: Integer) y
         unPaddedLen = length z

-- TODO: It would be nice if we could do away with this use of error.
-- Maybe using something from the following stackoverflow answer?
-- http://stackoverflow.com/questions/11910143/positive-integer-type
integerLog2 :: Integer -> Int
integerLog2 n | n <=0 = error "integerLog2: argument must be positive"
integerLog2 n = I# (integerLog2# n)
