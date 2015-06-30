{-# LANGUAGE ScopedTypeVariables #-}

module SSH.Crypto where

import qualified Codec.Crypto.SimpleAES as AES
import Control.Exception (ErrorCall(..), catchJust, evaluate)
import Control.Monad (replicateM)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Control.Monad.Trans.State (evalState)
import Data.ASN1.BinaryEncoding (BER(..), DER(..))
import Data.ASN1.Encoding (decodeASN1, encodeASN1)
import Data.ASN1.Stream (getConstructedEnd)
import Data.ASN1.Types (ASN1(..), ASN1ConstructionType(..))
import Data.Digest.Pure.SHA (bytestringDigest, sha1)
import Data.List (isPrefixOf)
import qualified Codec.Binary.Base64.String as B64
import qualified Codec.Crypto.RSA as RSA
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString as BS
import qualified OpenSSL.DSA as DSA

import qualified Crypto.Types.PubKey.RSA as RSAKey

import SSH.Packet (doPacket, integer, netLBS, netString, string)
import SSH.NetReader (readInteger, readString)
import SSH.Internal.Util
    ( fromBlocks, fromLBS, fromOctets, i2osp, integerLog2, strictLBS, toBlocks
    , toLBS)

-- Setup for the doctests.  Import additional modules.
-- $setup
-- >>> import Test.Tasty.QuickCheck (Positive(..))

-- | Setting for a cipher, including the 'CipherType', 'CipherMode',
-- blocksize, and keysize.
data Cipher =
    Cipher
        { cType :: CipherType
        , cMode :: CipherMode
        , cBlockSize :: Int
        , cKeySize :: Int
        }

-- | Types of ciphers that are supported.  Currently only 'AES'.
data CipherType = AES

-- | Cipher modes that are supported.  Currently only 'CBC'.
data CipherMode = CBC

-- | Type with information about HMAC, including the HMAC digest size and
-- the function to use to do the MACing.
data HMAC =
    HMAC
        { hDigestSize :: Int
        , hFunction :: LBS.ByteString -> LBS.ByteString
        }

-- | Information about an 'RSAPublicKey' or a 'DSAPublicKey'.
data PublicKey
    = RSAPublicKey
        { rpubE :: Integer  -- ^ @e * d = 1 mod L@
        , rpubN :: Integer  -- ^ @N = p * q@.  Used as modulus for pub and priv keys.
                            -- It's length in bits is the key length.
        }
    | DSAPublicKey
        { dpubP :: Integer
        , dpubQ :: Integer
        , dpubG :: Integer
        , dpubY :: Integer
        }
    deriving (Eq, Show)

-- | Similar to 'PublicKey', but for the private data.  It is unfortunate
-- that 'rprivPub' and 'dprivPub' are the same type.
data KeyPair
    = RSAKeyPair
        { rprivPub :: PublicKey
        , rprivD :: Integer            -- ^ @e * d = 1 mod L@
        , rprivPrime1 :: Integer       -- ^ @p@
        , rprivPrime2 :: Integer       -- ^ @q@
        , rprivExponent1 :: Integer
        , rprivExponent2 :: Integer
        , rprivCoefficient :: Integer
        }
    | DSAKeyPair
        { dprivPub :: PublicKey
        , dprivX :: Integer
        }
    deriving (Eq, Show)

-- | Read in a 'KeyPair' from a file on disk.  This uses 'parseKeyPair' to
-- do the parsing.
--
-- For an overview of the private key formats, see the documentation at
-- 'createAsn1FromKeyPair'.
keyPairFromFile :: FilePath -> IO KeyPair
keyPairFromFile fn = do
    x <- readFile fn
    return $ parseKeyPair x

-- | Remove the @\"-------BEGIN RSA PRIVATE KEY---------\"@ and
-- @\"-----END...\"@ strings from an ssh private key.  If you want to get
-- an idea of what a private key looks like, just look at
-- @/etc/ssh/ssh_host_rsa_key@.  Returns a string containing the type of
-- key (probably something like @\"RSA\"@ or @"\DSA\"@), and a list of
-- strings corresponding to the encoded key itself.
removeKeyPairHeaderFooter :: [String] -> (String, [String])
removeKeyPairHeaderFooter xs =
   (reverse . drop 17 . reverse . drop 11 . head $ xs, filter (not . ("--" `isPrefixOf`)) xs)

-- | This is the reverse of 'removeKeyPairHeaderFooter'.
addKeyPairHeaderFooter :: String   -- ^ type of key, something like \"RSA\"
                       -> [String] -- ^ the actual key value
                       -> [String]
addKeyPairHeaderFooter what xs =
   ["-----BEGIN " ++ what ++ " PRIVATE KEY-----"] ++ xs ++ ["-----END " ++ what ++ " PRIVATE KEY-----"]

-- | Parse an key pair from OpenSSH private key file format.
--
-- __WARNING__: This really makes too much use of 'error'.  Not safe :-\\.
parseKeyPair :: String -> KeyPair
parseKeyPair x =
    let (what, body) = removeKeyPairHeaderFooter . lines $ x
        asn1 = B64.decode . concat $ body
    in case decodeASN1 BER (toLBS asn1) of
        Right (Start Sequence:ss)
            | all isIntVal (fst $ getConstructedEnd 0 ss) ->
                let (is, _) = getConstructedEnd 0 ss
                in case what of
                    "RSA" ->
                        RSAKeyPair
                            { rprivPub = RSAPublicKey
                                { rpubE = intValAt 2 is
                                , rpubN = intValAt 1 is
                                }
                            , rprivD = intValAt 3 is
                            , rprivPrime1 = intValAt 4 is
                            , rprivPrime2 = intValAt 5 is
                            , rprivExponent1 = intValAt 6 is
                            , rprivExponent2 = intValAt 7 is
                            , rprivCoefficient = intValAt 8 is
                            }
                    "DSA" ->
                        DSAKeyPair
                            { dprivPub = DSAPublicKey
                            { dpubP = intValAt 1 is
                            , dpubQ = intValAt 2 is
                            , dpubG = intValAt 3 is
                            , dpubY = intValAt 4 is
                            }
                            , dprivX = intValAt 5 is
                            }
                    _ -> error ("unknown key type: " ++ what)
        Right u -> error ("unknown ASN1 decoding result: " ++ show u)
        Left e -> error ("ASN1 decoding of private key failed: " ++ show e)
  where
    -- | Return True if the 'ASN1' type is an 'IntVal'.
    isIntVal :: ASN1 -> Bool
    isIntVal (IntVal _) = True
    isIntVal _ = False

    -- | Return the Haskell 'Integer' value inside the 'IntVal' at the
    -- 'Int' index in the 'ASN1' list.  If value is not actually an
    -- 'IntVal', then throw an error.
    --
    -- This function should probably return a 'Maybe'.
    intValAt :: Int -> [ASN1] -> Integer
    intValAt i is =
        case is !! i of
            IntVal n -> n
            v -> error ("not an IntVal: " ++ show v)

-- | Create an 'ASN1' structure from a 'KeyPair'.
--
-- The ASN1 format for RSA private keys is defined here:
-- <http://tools.ietf.org/html/rfc3447#appendix-A.1>
--
-- The ASN1 format for a DSA private key looks like it was made up by
-- openssh, but you can find some details here:
-- <http://superuser.com/questions/478966/dsa-private-key-format>
--
-- Throws an error if passed an 'RSAKeyPair' containing an 'DSAPublicKey'
-- or the reverse.  This function should really return a Maybe (not throw
-- an error).
createAsn1FromKeyPair :: KeyPair -> [ASN1]
createAsn1FromKeyPair RSAKeyPair { rprivPub = RSAPublicKey { rpubE = e
                                                           , rpubN = n }
                                 , rprivD = d
                                 , rprivPrime1 = p1
                                 , rprivPrime2 = p2
                                 , rprivExponent1 = exp1
                                 , rprivExponent2 = exp2
                                 , rprivCoefficient = c
                                 } =
    [ Start Sequence
    , IntVal 0
    , IntVal n
    , IntVal e
    , IntVal d
    , IntVal p1
    , IntVal p2
    , IntVal exp1
    , IntVal exp2
    , IntVal c
    , End Sequence
    ]
createAsn1FromKeyPair DSAKeyPair { dprivPub = DSAPublicKey { dpubP = p
                                                           , dpubQ = q
                                                           , dpubG = g
                                                           , dpubY = y
                                                           }
                                 , dprivX = x
                                 } =
    [ Start Sequence
    , IntVal 0
    , IntVal p
    , IntVal q
    , IntVal g
    , IntVal y
    , IntVal x
    , End Sequence
    ]
createAsn1FromKeyPair _ = error "createAsn1FromKeyPair: unsupportedKeyPair"

-- | Turn a key pair into OpenSSH private key file format.
--
-- For an overview of the private key formats, see the documentation at
-- 'createAsn1FromKeyPair'.
printKeyPair :: KeyPair -> String
printKeyPair keyPair =
    unlines
      . addKeyPairHeaderFooter (keyTypeString keyPair)
      . lines
      . B64.encode
      . fromLBS
      . encodeASN1 DER
      $ createAsn1FromKeyPair keyPair
  where
    keyTypeString :: KeyPair -> String
    keyTypeString RSAKeyPair{} = "RSA"
    keyTypeString DSAKeyPair{} = "DSA"


-- | Generator for the "Second Oakley Group" described in RFC 2409.
--
-- <https://tools.ietf.org/html/rfc2409#section-6.2>
generator :: Integer
generator = 2

-- | Prime for the "Second Oakley Group" described in RFC 2409.
--
-- <https://tools.ietf.org/html/rfc2409#section-6.2>
safePrime :: Integer
safePrime = 179769313486231590770839156793787453197860296048756011706444423684197180216158519368947833795864925541502180565485980503646440548199239100050792877003355816639229553136239076508735759914822574862575007425302077447712589550957937778424442426617334727629299387668709205606050270810842907692932019128194467627007

-- | Returns the number of bytes of an 'RSAPublicKey' rounded down.
--
-- >>> rsaKeyLen $ RSAPublicKey 0 1
-- 0
-- >>> rsaKeyLen $ RSAPublicKey 0 $ 2^7 - 1
-- 0
-- >>> rsaKeyLen $ RSAPublicKey 0 $ 2^7
-- 1
-- >>> rsaKeyLen $ RSAPublicKey 0 $ 2^8
-- 1
-- >>> rsaKeyLen $ RSAPublicKey 0 $ 2^15
-- 2
-- >>> rsaKeyLen $ RSAPublicKey 0 $ 2^15 - 1
-- 1
--
-- There's no explicit indication of size in the key format so we just
-- have to look at the magnitude of the numbers.
-- This is consistent with what e.g. openssh does.
--
-- __WARNING__: Passing an 'RSAPublicKey' with a 'rpubN' that is
-- non-positive will result in an 'error'.
rsaKeyLen :: PublicKey -> Int
rsaKeyLen (RSAPublicKey _ n) = (1 + integerLog2 n) `div` 8
rsaKeyLen _ = error "rsaKeyLen: not an RSA public key"

-- | Turns a 'PublicKey' to a binary blob.  Used when doing authentication.
--
-- >>> let publicKey = RSAPublicKey 10 20
-- >>> blobToKey $ blob publicKey
-- RSAPublicKey {rpubE = 10, rpubN = 20}
--
-- Composing 'blobToKey' and 'blob' should always give us back the same thing.
--
-- prop> \(Positive e) (Positive n) -> let key = RSAPublicKey e n in blobToKey (blob key) == key
--
blob :: PublicKey -> LBS.ByteString
blob (RSAPublicKey e n) = doPacket $ do
    string "ssh-rsa"
    integer e
    integer n
blob (DSAPublicKey p q g y) = doPacket $ do
    string "ssh-dss"
    integer p
    integer q
    integer g
    integer y

-- | Turn a binary blob to a 'PublicKey'.
--
-- See documentation for 'blob'.
blobToKey :: LBS.ByteString -> PublicKey
blobToKey s = flip evalState s $ do
    t <- readString

    case t of
        "ssh-rsa" -> do
            e <- readInteger
            n <- readInteger
            return $ RSAPublicKey e n
        "ssh-dss" -> do
            [p, q, g, y] <- replicateM 4 readInteger
            return $ DSAPublicKey p q g y
        u -> error $ "unknown public key format: " ++ u

-- | Return signature for message.
--
-- RSA uses 'RSA.rsassa_pkcs1_v1_5_sign, which looks like it takes the
-- original message, SHA1's it, and then computes the signature from the
-- digest.
--
-- DSA first computes the digest using 'sha1' and then signs the digest
-- using 'DSA.signDigestedDataWithDSA'.
--
-- __WARNING__: If this is called with a 'RSAKeyPair' that contains
-- a 'DSAPublicKey' (or the reverse), it will throw 'error'.
sign :: (MonadIO m) => KeyPair              -- ^ key
                    -> LBS.ByteString       -- ^ message
                    -> m LBS.ByteString     -- ^ signature
sign (RSAKeyPair p@(RSAPublicKey e n) d _ _ _ _ _) message = do
  let keyLen = rsaKeyLen p
      publicKey = RSAKey.PublicKey keyLen n e
      privateKey = RSAKey.PrivateKey publicKey d 0 0 0 0 0
      signature = RSA.rsassa_pkcs1_v1_5_sign RSA.ha_SHA1 privateKey message
  return $ LBS.concat
    [ netString "ssh-rsa"
    , netLBS signature
    ]
sign (DSAKeyPair (DSAPublicKey p q g y) x) m = do
    let digest = strictLBS . bytestringDigest . sha1 $ m
        dsaKeyPair = DSA.tupleToDSAKeyPair (p, q, g, y, x)
    (r, s) <- liftIO $ DSA.signDigestedDataWithDSA dsaKeyPair digest
    return $ LBS.concat
        [ netString "ssh-dss"
        , netLBS $ LBS.concat
            [ LBS.pack $ i2osp 20 r
            , LBS.pack $ i2osp 20 s
            ]
        ]
sign _ _ = error "sign: invalid key pair"

-- | The length of the actual signature for a given key.
-- The actual signature data is always found at the end of a complete signature,
-- so can be extracted by just grabbing this many bytes at the end.
--
-- DSA keys always produce signatures of length 40 bytes. The length of
-- signatures of RSA keys is calculated with 'rsaKeyLen'.
actualSignatureLength :: PublicKey -> Int
actualSignatureLength p@(RSAPublicKey {}) = rsaKeyLen p
actualSignatureLength (DSAPublicKey {}) = 40

-- | Verify a signature for a message with a public key.
--
-- 'RSA.rsassa_pkcs1_v1_5_verify' is used for RSA, and
-- 'DSA.verifyDigestedDataWithDSA' is used for DSA.
verify :: MonadIO m
       => PublicKey          -- ^ key
       -> LBS.ByteString     -- ^ message
       -> LBS.ByteString     -- ^ signature
       -> m Bool            -- ^ true if signature is valid,
                             -- false if it isn't
verify p@(RSAPublicKey e n) message signature = do
    let keyLen = rsaKeyLen p
        -- TODO: Is it alright that we are dropping characters from the
        -- signature...?
        extraCharsToDrop = LBS.length signature - fromIntegral keyLen
        realSignature = LBS.drop extraCharsToDrop signature
        pubKey = RSAKey.PublicKey keyLen n e
        -- TODO: despite not being in IO, this RSA will sometimes throw errors.
        -- That probably shouldn't happen...
        unwrappedVerify = return $ RSA.rsassa_pkcs1_v1_5_verify RSA.ha_SHA1
                                                                pubKey
                                                                message
                                                                realSignature
    liftIO $ verifyCatchException unwrappedVerify

verify (DSAPublicKey p q g y) message signature = do
        -- TODO: Is it alright that we are dropping extra characters from
        -- the signature?  If the signature is too long, we probably should
        -- just be returning False...
    let realSignature = LBS.drop (LBS.length signature - 40) signature
        sigFirstHalf = LBS.take 20 realSignature
        sigSecondHalf = LBS.take 20 $ LBS.drop 20 realSignature
        r = fromOctets (256 :: Integer) $ LBS.unpack sigFirstHalf
        s = fromOctets (256 :: Integer) $ LBS.unpack sigSecondHalf
        pubKey = DSA.tupleToDSAPubKey (p, q, g, y)
        unwrappedVerify = DSA.verifyDigestedDataWithDSA pubKey digest (r, s)
    -- Unlike, RSA above, this doesn't appear to throw errors, even when
    -- fed weird data.
    liftIO $ verifyCatchException unwrappedVerify
  where
    digest :: BS.ByteString
    digest = strictLBS . bytestringDigest . sha1 $ message

-- | Helper function for 'verify'.  'verify' will throw IO errors. If an IO
-- error occurs, we need to catch it and return 'False' to indicate the
-- signature did not match the message.
verifyCatchException :: IO Bool -> IO Bool
verifyCatchException verifyIO =
    liftIO $ catchJust errorSelector (verifyIO >>= evaluate) errorHandler
  where
    errorSelector :: ErrorCall -> Maybe ()
    errorSelector (ErrorCall msg)
      | msg == "signature representative out of range" = Just ()
    errorSelector _ = Nothing

    errorHandler :: a -> IO Bool
    errorHandler _ = return False

encrypt :: Cipher -> BS.ByteString -> BS.ByteString -> LBS.ByteString -> (LBS.ByteString, BS.ByteString)
encrypt (Cipher AES CBC bs _) key vector m =
    ( fromBlocks encrypted
    , case encrypted of
          (_:_) -> strictLBS (last encrypted)
          [] -> error ("encrypted data empty for `" ++ show m ++ "' in encrypt") vector
    )
  where
    encrypted = toBlocks bs $ AES.crypt AES.CBC key vector AES.Encrypt m
