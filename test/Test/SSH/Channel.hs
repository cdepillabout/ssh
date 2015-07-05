{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}

module Test.SSH.Channel (sshChannelTests) where

#if __GLASGOW_HASKELL__ < 710
import Control.Applicative
#endif

import Test.Tasty (TestTree, testGroup)

-----------
-- Tests --
-----------

-- | TODO: tests.

sshChannelTests :: TestTree
sshChannelTests = testGroup "SSH/Channel.hs tests"
    [
    ]
