{-# LANGUAGE MagicHash #-}

{-|
Module      : SSH.Internal.Util
Description : Short description
Copyright   : (c) Alex Suraci, 2010
                  Dennis Gosnell, 2015
License     : BSD3
Maintainer  : Dennis Gosnell <cdep.illabout+hackage@gmail.com>
Stability   : experimental

Helper methods for the "SSH" module.
-}

module SSH.Internal.Util where

import Data.Word (Word8)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Data.Text (Text)
import qualified Data.Text as Text

import GHC.Base (Int(I#))
import GHC.Integer.Logarithms (integerLog2#)

-- Setup for the doctests.  Import additional modules.
-- $setup
-- >>> :set -XScopedTypeVariables
-- >>> import SSH.Internal.Util (toLBS)
-- >>> import Test.Tasty.QuickCheck (Positive(..))

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
-- [1,3,9,27,81,243]
--
-- __TODO__ This should normally be called with an Integer, or something able
-- to express arbitrarily large numbers.  If not, the numbers in the output
-- list will wrap around.
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
-- __TODO__ This shouldn't accept a number less than 2 as the first argument.
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

-- | Convert a number into an octet list with an arbitrary base.
--
-- >>> toOctets 256 513
-- [2,1]
-- >>> toOctets 256 4096
-- [16,0]
--
-- __TODO__ It doesn't make sense to pass the base as anything bigger than
-- 256, because they won't be able to be represented in the output list.
toOctets :: (Integral a, Integral b) => a -> b -> [Word8]
toOctets n = toBase n . fromIntegral

-- | Convert an octet list in an arbitrary base to the original number.
--
-- >>> fromOctets 128 [0,0,0,20]
-- 20
-- >>> fromOctets 256 [1,20]
-- 276
--
-- __TODO__ This function passes the first argument to 'powersOf', so the
-- note there applies here too.  Also, it doesn't make sense to pass a base
-- that is smaller than some of the numbers in the octet.  For instance, it
-- doesn't make sense to write @fromOctets 10 [20, 30, 40]@.
fromOctets :: (Integral a, Integral b) => a       -- ^ base to use
                                       -> [Word8] -- ^ octet list
                                       -> b
fromOctets n x =
    fromIntegral $ sum $
        zipWith (*) (powersOf n) (reverse (map fromIntegral x))

-- | Convert an 'Integral' to an octet list of a specified length, padded
-- if it is below that length.  If the resulting octet list is longer than
-- the specified  padding length, it won't be padded and an error won't be
-- thrown.  If the padding length is 0 or less, then no padding will be
-- done.
--
-- >>> i2osp 4 50
-- [0,0,0,50]
-- >>> i2osp 2 512
-- [2,0]
-- >>> i2osp 1 4096
-- [16,0]
-- >>> i2osp 0 50
-- [50]
--
-- This method is similar to the one documented in
-- <http://tools.ietf.org/html/rfc3447#page-9 rfc3447>.
--
-- __TODO__ Passing a negative number as the second argument results in the
-- method never returning.
i2osp :: Integral a => Int       -- ^ length of octet list
                    -> a         -- ^ 'Integral' to convert
                    -> [Word8]   -- ^ resulting octet list
i2osp padLength y = pad ++ z
  where
    pad :: [Word8]
    pad = replicate (padLength - unPaddedLen) (0x00::Word8)

    z :: [Word8]
    z = toOctets (256 :: Integer) y

    unPaddedLen :: Int
    unPaddedLen = length z

-- | Compute the log of a number.  Return 'error' if n is zero or less.
--
-- >>> integerLog2 32
-- 5
-- >>> integerLog2 1024
-- 10
-- >>> integerLog2 1000
-- 9
--
-- __TODO__ It would be nice if we could do away with this use of error.
-- Maybe using something from the following stackoverflow answer?
-- <http://stackoverflow.com/questions/11910143/positive-integer-type>
integerLog2 :: Integer -> Int
integerLog2 n | n <=0 = error "integerLog2: argument must be positive"
integerLog2 n = I# (integerLog2# n)

-- | Chop a 'LBS.ByteString' up into equal sized blocks.
--
-- >>> toBlocks 1 "hello"
-- ["h","e","l","l","o"]
-- >>> toBlocks 3 "hello"
-- ["hel","lo"]
-- >>> toBlocks 10 "hello"
-- ["hello"]
--
-- 'toBlocks' and 'fromBlocks' are more-or-less inverses.
--
-- prop> \(Positive blockSize) str -> (fromBlocks . toBlocks blockSize $ toLBS str) == toLBS str
--
-- __WARNING__:  Using a non-positive blocksize will result in this
-- function never returning.  This should be fixed.
toBlocks :: (Integral a) => a -> LBS.ByteString -> [LBS.ByteString]
toBlocks _ m | m == LBS.empty = []
toBlocks bs m = b : rest
  where
    b = LBS.take (fromIntegral bs) m
    rest = toBlocks bs (LBS.drop (fromIntegral bs) m)

-- | Defined as 'LBS.concat'.
--
-- >>> fromBlocks ["hello", " my n", "ame i", "s SPJ"]
-- "hello my name is SPJ"
fromBlocks :: [LBS.ByteString] -> LBS.ByteString
fromBlocks = LBS.concat

-- | Like 'show' but outputs 'Text'.
tshow :: Show a => a -> Text
tshow = Text.pack . show

-- | Instance for MonadRandom
