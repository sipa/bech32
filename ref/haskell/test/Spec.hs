import Codec.Binary.Bech32 (DecodeError (..), EncodeError (..), Bech32Type(..),
                            bech32Decode, bech32Encode, bech32Spec,
                            segwitDecode, segwitEncode, word5)
import Control.Monad (forM_)
import Data.Bits (xor)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as BSC
import Data.Char (toLower)
import Data.Maybe (isJust, isNothing)
import Data.Word (Word8)
import Test.Tasty
import Test.Tasty.HUnit

main :: IO ()
main = defaultMain tests

validChecksums :: [(Bech32Type, BS.ByteString)]
validChecksums = [(b32type, BSC.pack string)
  | (b32type, string) <-
    [ (Bech32, "A12UEL5L")
    , (Bech32, "a12uel5l")
    , (Bech32, "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs")
    , (Bech32, "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw")
    , (Bech32, "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j")
    , (Bech32, "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w")
    , (Bech32m, "A1LQFN3A")
    , (Bech32m, "a1lqfn3a")
    , (Bech32m, "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6")
    , (Bech32m, "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx")
    , (Bech32m, "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8")
    , (Bech32m, "split1checkupstagehandshakeupstreamerranterredcaperredlc445v")
 ] ]

invalidChecksums :: [(Bech32Type, BS.ByteString)]
invalidChecksums = [(b32type, BSC.pack string)
  | (b32type, string) <-
    [ (Bech32, " 1nwldj5")
    , (Bech32, "\DEL1axkwrx")
    , (Bech32, "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx")
    , (Bech32, "pzry9x0s0muk")
    , (Bech32, "1pzry9x0s0muk")
    , (Bech32, "x1b4n0q5v")
    , (Bech32, "li1dgmt3")
    , (Bech32, "de1lg7wt\xFF")
    , (Bech32, "A1G7SGD8")
    , (Bech32, "10a06t8")
    , (Bech32, "1qzzfhee")
    , (Bech32m, " 1xj0phk")
    , (Bech32m, "\x79" ++ "1g6xzxy")
    , (Bech32m, "\x80" ++ "1vctc34")
    , (Bech32m, "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4")
    , (Bech32m, "qyrz8wqd2c9m")
    , (Bech32m, "1qyrz8wqd2c9m")
    , (Bech32m, "y1b0jsk6g")
    , (Bech32m, "lt1igcx5c0")
    , (Bech32m, "in1muywd")
    , (Bech32m, "mm1crxm3i")
    , (Bech32m, "au1s5cgom")
    , (Bech32m, "M1VUXWEZ")
    , (Bech32m, "16plkw9")
    , (Bech32m, "1p2gdwpf")
  ] ]

validAddresses :: [(BS.ByteString, BS.ByteString)]
validAddresses = map mapTuple
    [ ("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", "0014751e76e8199196d454941c45d1b3a323f1433bd6")
    , ("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"
      ,"00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262")
    , ("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y"
      ,"5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6")
    , ("BC1SW50QGDZ25J", "6002751e")
    , ("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", "5210751e76e8199196d454941c45d1b3a323")
    , ("tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy"
      ,"0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433")
    , ("tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c"
      ,"5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433")
    , ("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
      ,"512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    ]
  where
    mapTuple (a, b) = (BSC.pack a, BSC.pack b)

invalidAddresses :: [BS.ByteString]
invalidAddresses = map BSC.pack
    [ "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty"
    , "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"
    , "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2"
    , "bc1rw5uspcuh"
    , "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90"
    , "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P"
    , "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7"
    , "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du"
    , "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv"
    , "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut"
    , "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd"
    , "tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf"
    , "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL"
    , "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh"
    , "tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47"
    , "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4"
    , "BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R"
    , "bc1pw5dgrnzv"
    , "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav"
    , "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P"
    , "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq"
    , "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf"
    , "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j"
    , "bc1gmk9yu"
    ]

hexDecode :: BS.ByteString -> BS.ByteString
hexDecode s = either error id $ B16.decode s

segwitScriptPubkey :: Word8 -> [Word8] -> BS.ByteString
segwitScriptPubkey witver witprog = BS.pack $ witver' : (fromIntegral $ length witprog) : witprog
  where witver' = if witver == 0 then 0 else witver + 0x50

tests :: TestTree
tests = testGroup "Tests"
    [ testCase "Checksums" $ forM_ validChecksums $ \(b32type, checksum) -> do
          let spec = bech32Spec b32type
          case bech32Decode checksum of
            Left err -> assertFailure (show checksum ++ ", " ++ show err)
            Right (residue, resultHRP, resultData) -> do
                assertEqual (show checksum ++ " spec") spec residue
                -- test that a corrupted checksum fails decoding.
                let (hrp, rest) = BSC.breakEnd (== '1') checksum
                    Just (first, rest') = BS.uncons rest
                    checksumCorrupted = (hrp `BS.snoc` (first `xor` 1)) `BS.append` rest'
                assertBool (show checksum ++ " corrupted") $ isCorrupted spec (bech32Decode checksumCorrupted)
                -- test that re-encoding the decoded checksum results in the same checksum.
                let checksumEncoded = bech32Encode spec resultHRP resultData
                    expectedChecksum = Right $ BSC.map toLower checksum
                assertEqual (show checksum ++ " re-encode") expectedChecksum checksumEncoded
    , testCase "Invalid checksums" $ forM_ invalidChecksums $
          \(b32type, checksum) -> assertBool (show checksum) $ isCorrupted (bech32Spec b32type) (bech32Decode checksum)
    , testCase "Addresses" $ forM_ validAddresses $ \(address, hexscript) -> do
          let address' = BSC.map toLower address
              hrp = BSC.take 2 address'
          case segwitDecode hrp address of
            Nothing -> assertFailure "decode failed"
            Just (witver, witprog) -> do
                assertEqual (show address) (hexDecode hexscript) (segwitScriptPubkey witver witprog)
                assertEqual (show address) (Just address') (segwitEncode hrp witver witprog)
    , testCase "Invalid Addresses" $ forM_ invalidAddresses $ \address -> do
          assertBool (show address) (isNothing $ segwitDecode (BSC.pack "bc") address)
          assertBool (show address) (isNothing $ segwitDecode (BSC.pack "tb") address)
    , testCase "More Encoding/Decoding Cases" $ do
          assertBool "length > 90" $ isError ResultStringLengthExceeded $
              bech32Encode 1 (BSC.pack "bc") (replicate 82 (word5 (1::Word8)))
          assertBool "segwit version bounds" $ isNothing $
              segwitEncode (BSC.pack "bc") 17 []
          assertBool "segwit prog len version 0" $ isNothing $
              segwitEncode (BSC.pack "bc") 0 (replicate 30 1)
          assertBool "segwit prog len version != 0" $ isJust $
              segwitEncode (BSC.pack "bc") 1 (replicate 30 1)
          assertBool "segwit prog len version != 0" $ isNothing $
              segwitEncode (BSC.pack "bc") 1 (replicate 41 1)
          assertBool "empty HRP encode" $ isError InvalidHumanReadablePart $ bech32Encode 1 (BSC.pack "") []
          assertBool "empty HRP decode" $ isError InvalidHRP $ bech32Decode (BSC.pack "10a06t8")
          assertEqual "hrp lowercased"
              (Right $ BSC.pack "hrp1g9xj8m")
              (bech32Encode 1 (BSC.pack "HRP") [])
    ]

isError :: Eq a => a -> Either a b -> Bool
isError e' (Left e) = e == e'
isError _ _         = False

isCorrupted :: Word -> Either x (Word, y, z) -> Bool
isCorrupted _ (Left _) = True
isCorrupted spec (Right (resultSpec, _, _)) = spec /= resultSpec
