module SSH.Supported where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import qualified Data.Serialize as S
import Crypto.HMAC (MacKey(..), hmac)
import Crypto.Hash.CryptoAPI (MD5, SHA1)

import SSH.Crypto
import SSH.Internal.Util


version :: String
version = "SSH-2.0-DarcsDen"

-- | The required key exchange algorithms are specified in
-- <https://tools.ietf.org/html/rfc4253#section-6.5 rfc4253 section 6.5>.
supportedKeyExchanges :: [String]
supportedKeyExchanges =
    [ "diffie-hellman-group1-sha1"
    -- TODO: The SSH rfc requires that the following method is also
    -- supported.
    -- , "diffie-hellman-group-exchange-sha1"
    ]

-- | The supported key algorithms.  Specified in
-- <https://tools.ietf.org/html/rfc4253#section-6.6 rfc4253 section 6.6>.
supportedKeyAlgorithms :: [String]
supportedKeyAlgorithms = ["ssh-rsa", "ssh-dss"]

-- | Suporrted Ciphers.
--
-- Defined in <https://tools.ietf.org/html/rfc4253#section-6.3 rfc4253
-- section 6.3>.
supportedCiphers :: [(String, Cipher)]
supportedCiphers =
    [ ("aes256-cbc", aesCipher 32)
    , ("aes192-cbc", aesCipher 24)
    , ("aes128-cbc", aesCipher 16)
    ]
  where
    aesCipher :: Int -> Cipher
    aesCipher s = Cipher AES CBC 16 s

-- | The required macs are specified in
-- <https://tools.ietf.org/html/rfc4253#section-6.4 rfc4253 section 6.4>.
supportedMACs :: [(String, LBS.ByteString -> HMAC)]
supportedMACs =
    [ ("hmac-sha1", sha)
    , ("hmac-md5", md5)
    ]
  where
    sha, md5 :: LBS.ByteString -> HMAC
    sha k = HMAC 20 $ \b -> bsToLBS . S.runPut $ S.put (hmac (MacKey (strictLBS (LBS.take 20 k))) b :: SHA1)
    md5 k = HMAC 16 $ \b -> bsToLBS . S.runPut $ S.put (hmac (MacKey (strictLBS (LBS.take 16 k))) b :: MD5)

    bsToLBS :: BS.ByteString -> LBS.ByteString
    bsToLBS = LBS.fromChunks . (: [])

-- | Supported compression algorithms.
--
-- Defined in <https://tools.ietf.org/html/rfc4253#section-6.2 rfc4253
-- section 6.2>.
supportedCompression :: String
supportedCompression = "none"

supportedLanguages :: String
supportedLanguages = ""

