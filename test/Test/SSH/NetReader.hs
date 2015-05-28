{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}

module Test.SSH.NetReader (sshNetReaderTests) where

#if __GLASGOW_HASKELL__ < 710
import Control.Applicative
#endif

import Test.Tasty (TestTree, testGroup)

-- Currently everything is covered, by the doctests, so this file is just
-- a placeholder...

sshNetReaderTests :: TestTree
sshNetReaderTests = testGroup "SSH/NetReader.hs tests"
    [ ]


