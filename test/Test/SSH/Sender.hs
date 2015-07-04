{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}

module Test.SSH.Sender (sshSenderTests) where

#if __GLASGOW_HASKELL__ < 710
import Control.Applicative
#endif

import Test.Tasty (TestTree, testGroup)

-----------
-- Tests --
-----------

-- | TODO: tests.

sshSenderTests :: TestTree
sshSenderTests = testGroup "SSH/Sender.hs tests"
    [
    ]
