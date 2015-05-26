{-# LANGUAGE CPP #-}

module Test.Util where

#if __GLASGOW_HASKELL__ < 710
import Control.Applicative
#endif

import qualified Data.ByteString.Lazy as LBS
import Test.QuickCheck (Arbitrary(..))

newtype ArbitraryLazyByteString = ArbitraryLazyByteString LBS.ByteString
    deriving Show

instance Arbitrary ArbitraryLazyByteString where
  arbitrary = ArbitraryLazyByteString . LBS.pack <$> arbitrary

