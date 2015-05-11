module Test.Util where

import qualified Data.ByteString.Lazy as LBS
import Test.QuickCheck (Arbitrary(..))

instance Arbitrary LBS.ByteString where
  arbitrary = LBS.pack <$> arbitrary

