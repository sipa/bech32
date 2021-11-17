module Codec.Binary.Bech32
  (
    DecodeError(..)
  , EncodeError(..)
  , Bech32Type(..)

  , bech32Encode
  , bech32Decode
  , bech32Spec
  , toBase32
  , toBase256
  , segwitEncode
  , segwitDecode
  , Word5()
  , word5
  , fromWord5
  ) where

import Control.Monad (guard)
import qualified Data.Array as Arr
import Data.Bits (Bits, testBit, unsafeShiftL, unsafeShiftR, xor, (.&.), (.|.))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import Data.Char (toLower, toUpper)
import Data.Foldable (foldl')
import Data.Functor.Identity (Identity, runIdentity)
import Data.Ix (Ix (..))
import Data.Word (Word8)

type HRP = BS.ByteString
type Data = [Word8]

(.>>.), (.<<.) :: Bits a => a -> Int -> a
(.>>.) = unsafeShiftR
(.<<.) = unsafeShiftL

newtype Word5 = UnsafeWord5 Word8
              deriving (Eq, Ord, Show)

instance Ix Word5 where
  range (UnsafeWord5 m, UnsafeWord5 n) = map UnsafeWord5 $ range (m, n)
  index (UnsafeWord5 m, UnsafeWord5 n) (UnsafeWord5 i) = index (m, n) i
  inRange (m,n) i = m <= i && i <= n

word5 :: Integral a => a -> Word5
word5 x = UnsafeWord5 ((fromIntegral x) .&. 31)
{-# INLINE word5 #-}
{-# SPECIALIZE INLINE word5 :: Word8 -> Word5 #-}

fromWord5 :: Num a => Word5 -> a
fromWord5 (UnsafeWord5 x) = fromIntegral x
{-# INLINE fromWord5 #-}
{-# SPECIALIZE INLINE fromWord5 :: Word5 -> Word8 #-}

charset :: Arr.Array Word5 Char
charset = Arr.listArray (UnsafeWord5 0, UnsafeWord5 31) "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

charsetMap :: Char -> Maybe Word5
charsetMap c | inRange (Arr.bounds inv) upperC = inv Arr.! upperC
             | otherwise = Nothing
  where
    upperC = toUpper c
    inv = Arr.listArray ('0', 'Z') (repeat Nothing) Arr.// (map swap (Arr.assocs charset))
    swap (a, b) = (toUpper b, Just a)

bech32Polymod :: [Word5] -> Word
bech32Polymod values = foldl' go 1 values .&. 0x3fffffff
  where
    go chk value = foldl' xor chk' [g | (g, i) <- zip generator [25..], testBit chk i]
      where
        generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        chk' = chk .<<. 5 `xor` (fromWord5 value)

bech32HRPExpand :: HRP -> [Word5]
bech32HRPExpand hrp = map (UnsafeWord5 . (.>>. 5)) (BS.unpack hrp) ++ [UnsafeWord5 0] ++ map word5 (BS.unpack hrp)

bech32CreateChecksum :: Word -> HRP -> [Word5] -> [Word5]
bech32CreateChecksum residue hrp dat = [word5 (polymod .>>. i) | i <- [25,20..0]]
  where
    values = bech32HRPExpand hrp ++ dat
    polymod = bech32Polymod (values ++ map UnsafeWord5 [0, 0, 0, 0, 0, 0]) `xor` residue

bech32Residue :: HRP -> [Word5] -> Word
bech32Residue hrp dat = bech32Polymod (bech32HRPExpand hrp ++ dat)

data EncodeError =
      ResultStringLengthExceeded
    | InvalidHumanReadablePart
    deriving (Show, Eq)

bech32Encode :: Word -> HRP -> [Word5] -> Either EncodeError BS.ByteString
bech32Encode residue hrp dat = do
    verify InvalidHumanReadablePart $ validHRP hrp
    let dat' = dat ++ bech32CreateChecksum residue hrp dat
        rest = map (charset Arr.!) dat'
        result = BSC.concat [BSC.map toLower hrp, BSC.pack "1", BSC.pack rest]
    verify ResultStringLengthExceeded $ BS.length result <= 90
    return result

validHRP :: BS.ByteString -> Bool
validHRP hrp = not (BS.null hrp) && BS.all (\char -> char >= 33 && char <= 126) hrp

data DecodeError =
    Bech32StringLengthExceeded
  | CaseInconsistency
  | TooShortDataPart
  | InvalidHRP
  | ChecksumVerificationFail
  | InvalidCharsetMap
  deriving (Show, Eq)

bech32Decode :: BS.ByteString -> Either DecodeError (Word, HRP, [Word5])
bech32Decode bech32 = do
    verify Bech32StringLengthExceeded $ BS.length bech32 <= 90
    verify CaseInconsistency $ validCase bech32
    let (hrp, dat) = BSC.breakEnd (== '1') $ BSC.map toLower bech32
    verify TooShortDataPart $ BS.length dat >= 6
    hrp' <- maybeToRight InvalidHRP $ BSC.stripSuffix (BSC.pack "1") hrp
    verify InvalidHRP $ validHRP hrp'
    dat' <- maybeToRight InvalidCharsetMap . mapM charsetMap $ BSC.unpack dat
    let residue = bech32Residue hrp' dat'
    return (residue, hrp', take (BS.length dat - 6) dat')
      where
        validCase :: BS.ByteString -> Bool
        validCase b32 = BSC.map toUpper b32 == b32 || BSC.map toLower b32 == b32

type Pad f = Int -> Int -> Word -> [[Word]] -> f [[Word]]

yesPadding :: Pad Identity
yesPadding _ 0 _ result        = return result
yesPadding _ _ padValue result = return $ [padValue] : result
{-# INLINE yesPadding #-}

noPadding :: Pad Maybe
noPadding frombits bits padValue result = do
    guard $ bits < frombits && padValue == 0
    return result
{-# INLINE noPadding #-}

-- Big endian conversion of a bytestring from base 2^frombits to base 2^tobits.
-- frombits and twobits must be positive and 2^frombits and 2^tobits must be smaller than the size of Word.
-- Every value in dat must be strictly smaller than 2^frombits.
convertBits :: Functor f => [Word] -> Int -> Int -> Pad f -> f [Word]
convertBits dat frombits tobits pad = fmap (concat . reverse) $ go dat 0 0 []
  where
    go [] acc bits result =
        let padValue = (acc .<<. (tobits - bits)) .&. maxv
        in pad frombits bits padValue result
    go (value:dat') acc bits result = go dat' acc' (bits' `rem` tobits) (result':result)
      where
        acc' = (acc .<<. frombits) .|. fromIntegral value
        bits' = bits + frombits
        result' = [(acc' .>>. b) .&. maxv | b <- [bits'-tobits,bits'-2*tobits..0]]
    maxv = (1 .<<. tobits) - 1
{-# INLINE convertBits #-}

toBase32 :: [Word8] -> [Word5]
toBase32 dat = map word5 $ runIdentity $ convertBits (map fromIntegral dat) 8 5 yesPadding

toBase256 :: [Word5] -> Maybe [Word8]
toBase256 dat = fmap (map fromIntegral) $ convertBits (map fromWord5 dat) 5 8 noPadding

data Bech32Type = Bech32
                | Bech32m

bech32Spec :: Bech32Type -> Word
bech32Spec Bech32 = 1
bech32Spec Bech32m = 0x2bc830a3

segwitCheck :: Word8 -> Data -> Maybe Bech32Type
segwitCheck witver witprog = do
    guard $ witver <= 16
    if witver == 0
    then guard (length witprog == 20 || length witprog == 32) >> return Bech32
    else guard (length witprog >= 2 && length witprog <= 40) >> return Bech32m

segwitDecode :: HRP -> BS.ByteString -> Maybe (Word8, Data)
segwitDecode hrp addr = do
    (residue, hrp', dat) <- rightToMaybe $ bech32Decode addr
    guard $ (hrp == hrp') && not (null dat)
    let (UnsafeWord5 witver : datBase32) = dat
    decoded <- toBase256 datBase32
    b32type <- segwitCheck witver decoded
    guard $ bech32Spec b32type == residue
    return (witver, decoded)

segwitEncode :: HRP -> Word8 -> Data -> Maybe BS.ByteString
segwitEncode hrp witver witprog = do
    b32type <- segwitCheck witver witprog
    rightToMaybe $ bech32Encode (bech32Spec b32type) hrp $ UnsafeWord5 witver : toBase32 witprog

rightToMaybe :: Either l r -> Maybe r
rightToMaybe = either (const Nothing) Just

maybeToRight :: l -> Maybe r -> Either l r
maybeToRight l = maybe (Left l) Right

verify :: a -> Bool -> Either a ()
verify _ True  = Right ()
verify v False = Left v
