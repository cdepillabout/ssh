{-# LANGUAGE CPP #-}

module Test.Util where

#if __GLASGOW_HASKELL__ < 710
import Control.Applicative
#endif

import qualified Data.ByteString.Lazy as LBS
import Test.QuickCheck (Arbitrary(..))

instance Arbitrary LBS.ByteString where
  arbitrary = LBS.pack <$> arbitrary

