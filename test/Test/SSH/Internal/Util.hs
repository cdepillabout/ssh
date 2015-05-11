module Test.SSH.Internal.Util (sshInternalUtilTests) where

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck (testProperty)

import SSH.Internal.Util (fromLBS, toLBS)

import Test.Util ()

toFromLBS :: TestTree
toFromLBS = testProperty "(toLBS . fromLBS) x == x" $
    \lazyByteString -> (toLBS . fromLBS) lazyByteString == lazyByteString

fromToLBS :: TestTree
fromToLBS = testProperty "(fromLBS . toLBS) x == x" $
    \string -> (fromLBS . toLBS) string == string

sshInternalUtilTests :: TestTree
sshInternalUtilTests = testGroup "SSH/Util.hs tests"
    [ fromToLBS
    , toFromLBS
    ]
