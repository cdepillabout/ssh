{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}

module Test.SSH.NetReader (sshNetReaderTests) where

#if __GLASGOW_HASKELL__ < 710
import Control.Applicative
#endif

import qualified Data.ByteString.Lazy as LBS
import Data.Char (ord)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit ((@?=), testCase)
import Test.Tasty.QuickCheck ((==>), Positive(..), testProperty)

import SSH.Packet (byte, long, mpint, packetLength, unmpint)

import Test.Util (ArbitraryLBS(..), ArbitraryNonEmptyLBS(..))

packetLengthTestEmptyPacket :: TestTree
packetLengthTestEmptyPacket = testCase "test for packetLength with empty Packet" $
    packetLength (return ()) @?= 0

packetLengthTest :: TestTree
packetLengthTest = testCase "simple test for packetLength" $
    packetLength (byte 1 >> long 1) @?= 5

unmpintShouldNeverFail :: TestTree
unmpintShouldNeverFail = testProperty "unmpint should never fail" $
    \(ArbitraryLBS lazyByteString) ->
        let result = unmpint lazyByteString
        in result == result

unmpintIsReverseOfMpint :: TestTree
unmpintIsReverseOfMpint = testProperty "unmpint is sort of the reverse of mpint" $
    \(Positive integer) -> integer == (unmpint . LBS.drop 4 $ mpint integer)

mpintIsReverseOfUnmpint :: TestTree
mpintIsReverseOfUnmpint = testProperty "mpint is sort of the reverse of unmpint" $
    \(ArbitraryNonEmptyLBS nonEmptyLBS) ->
        let integer = unmpint nonEmptyLBS
            nonEmptyLBSNoNuls = removeLeadingNuls nonEmptyLBS
            result = removeLeadingNuls . LBS.drop 4 $ mpint integer
        in integer > 0 ==>
            nonEmptyLBSNoNuls == result
  where
      removeLeadingNuls :: LBS.ByteString -> LBS.ByteString
      removeLeadingNuls = LBS.dropWhile (== fromIntegral (ord '\NUL'))

sshNetReaderTests :: TestTree
sshNetReaderTests = testGroup "SSH/NetReader.hs tests"
    [ mpintIsReverseOfUnmpint
    , packetLengthTest
    , packetLengthTestEmptyPacket
    , unmpintIsReverseOfMpint
    , unmpintShouldNeverFail
    ]


