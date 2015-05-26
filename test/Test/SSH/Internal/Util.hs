{-# LANGUAGE CPP #-}

module Test.SSH.Internal.Util (sshInternalUtilTests) where

#if __GLASGOW_HASKELL__ < 710
import Control.Applicative
#endif

import qualified Data.ByteString.Char8 as Char8
import Test.QuickCheck (choose, elements, listOf)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck (testProperty)

import SSH.Internal.Util (fromLBS, fromOctets, powersOf, strictLBS, toBase, toLBS, toOctets)

import Test.Util (ArbitraryLazyByteString(..))

toFromLBSTest :: TestTree
toFromLBSTest = testProperty "(toLBS . fromLBS) x == x" $
    \(ArbitraryLazyByteString lazyByteString) ->
        (toLBS . fromLBS) lazyByteString == lazyByteString

fromToLBSTest :: TestTree
fromToLBSTest = testProperty "(fromLBS . toLBS) x == x" $
    \string -> (fromLBS . toLBS) string == string

strictLBSTest :: TestTree
strictLBSTest = testProperty "converting to strict bytestring works" $
    \string -> (strictLBS . toLBS) string == Char8.pack string

powersOfTest :: TestTree
powersOfTest = testProperty "powersOf generates powers of a number" $ do
    n <- elements $ [-100..(-1)] ++ [1..100]
    let powers = powersOf (n::Integer)
        -- if n is 3, then this creates a list of tuples like
        -- [(1,3), (3, 9), (9, 27), (27, 81), ...]
        powersZipped = take 20 $ zip powers $ tail powers
    return $ all (\(a, b) -> b `div` a == n) powersZipped

toBaseTest :: TestTree
toBaseTest = testProperty "toBase can be converted back to original number" $ do
    base <- choose (2, 1000)
    n <- choose (0::Integer, 1000)
    let newBase = toBase base n
        revNewBase = reverse newBase
        powersOfBase = powersOf base
        zipped = zipWith (*) powersOfBase revNewBase
        originalN = sum zipped
    return $ originalN == n

toFromOctetsTest :: TestTree
toFromOctetsTest = testProperty "(toOctets . fromOctets) x == x" $ do
    base <- choose (2::Integer, 256)
    n <- dropWhile (== 0) <$> listOf (choose (0, (fromIntegral base) - 1))
    let from = fromOctets base n :: Integer
        to = toOctets base from
    return $ to == n

fromToOctetsTest :: TestTree
fromToOctetsTest = testProperty "(fromOctets . toOctets) x == x" $ do
    base <- choose (2::Integer, 256)
    n <- choose (0, 100000000000000)
    let to = toOctets base n
        from = fromOctets base to :: Integer
    return $ from == n

sshInternalUtilTests :: TestTree
sshInternalUtilTests = testGroup "SSH/Util.hs tests"
    [ fromToLBSTest
    , fromToOctetsTest
    , strictLBSTest
    , powersOfTest
    , toBaseTest
    , toFromLBSTest
    , toFromOctetsTest
    ]
