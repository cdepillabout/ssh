module Test.SSH.Internal.Util (sshInternalUtilTests) where

import qualified Data.ByteString.Char8 as Char8 (pack)
import Test.QuickCheck (choose, elements)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck (testProperty)

import SSH.Internal.Util (fromLBS, powersOf, strictLBS, toBase, toLBS)

import Test.Util ()

toFromLBSTest :: TestTree
toFromLBSTest = testProperty "(toLBS . fromLBS) x == x" $
    \lazyByteString -> (toLBS . fromLBS) lazyByteString == lazyByteString

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
    -- n <- (arbitrary :: Gen Integer)
    n <- choose (0::Integer, 1000)
    base <- choose (2, 1000)
    let newBase = toBase base n
        revNewBase = reverse newBase
        powersOfBase = powersOf base
        zipped = zipWith (*) powersOfBase revNewBase
        originalN = sum zipped
    return $ originalN == n

sshInternalUtilTests :: TestTree
sshInternalUtilTests = testGroup "SSH/Util.hs tests"
    [ fromToLBSTest
    , strictLBSTest
    , powersOfTest
    , toBaseTest
    , toFromLBSTest
    ]
