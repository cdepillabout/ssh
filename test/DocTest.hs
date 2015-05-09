module Main (main) where

import System.FilePath.Glob (glob)
import Test.DocTest (doctest)

main :: IO ()
main = do
    srcFiles <- glob "src/**/*.hs"
    let ghcOptions = [ "-XOverloadedStrings"
                     ]
    doctest $ ghcOptions ++ srcFiles
