
module Main where

import SSH (start)
import SSH.Channel (defaultChannelConfig)
import SSH.Crypto (keyPairFromFile)
import SSH.Session (SessionConfig(..), defaultSessionConfig)



main :: IO ()
main = do
    keyPair <- keyPairFromFile "./sample-key-pair"
    let sessionConfig = defaultSessionConfig
                            { scKeyPair = keyPair
                            }
        channelConfig = defaultChannelConfig
    start sessionConfig channelConfig 12345
