module SSH.Debug where

import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as LBS
import Debug.Trace
import Numeric (showHex)

debugging :: Bool
debugging = False

debug :: (Show a, Show b) => b -> a -> a
debug s v
    | debugging = trace (show s ++ ": " ++ show v) v
    | otherwise = v

dump :: (Monad m, Show a) => a -> m ()
dump x
    | debugging = trace (show x) (return ())
    | otherwise = return ()

showHexLazyByteString :: ByteString -> [String]
showHexLazyByteString = map (flip showHex "") . LBS.unpack

