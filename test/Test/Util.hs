{-# LANGUAGE CPP #-}

module Test.Util where

#if __GLASGOW_HASKELL__ < 710
import Control.Applicative
#endif

import qualified Data.ByteString.Lazy as LBS
import Test.QuickCheck (Arbitrary(..), suchThat)

newtype ArbitraryLBS = ArbitraryLBS LBS.ByteString
    deriving Show

instance Arbitrary ArbitraryLBS where
    arbitrary = ArbitraryLBS . LBS.pack <$> arbitrary

newtype ArbitraryNonEmptyLBS = ArbitraryNonEmptyLBS LBS.ByteString
    deriving Show

instance Arbitrary ArbitraryNonEmptyLBS where
    arbitrary =
        let nonEmptyString = suchThat arbitrary $ not . null
        in ArbitraryNonEmptyLBS . LBS.pack <$> nonEmptyString


