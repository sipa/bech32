// Copyright (c) 2017 Pieter Wuille
// Copyright (c) 2017 mruddy
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package com.github.mruddy.bip173;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import javax.xml.bind.DatatypeConverter;
import org.junit.Assert;
import org.junit.Test;
import com.github.mruddy.bip173.Bech32.DecodingResult;

public class Bech32Test {
  private static final byte[] EMPTY = {};

  @Test
  public void test_decode_vectors() throws Exception {
    final Map<String, Bech32.DecodingResult> vectors = new LinkedHashMap<>();
    vectors.put(null, null);
    vectors.put(null, null); //
    vectors.put("", null); //
    vectors.put(" ", null); //
    vectors.put("0", null); //
    vectors.put("1", null); //
    vectors.put("123456", null); //
    vectors.put("1234567", null); //
    vectors.put("12345678", null); //
    vectors.put("012345", null); //
    vectors.put("0123456", null); //
    vectors.put("01234567", null); //
    vectors.put("10a06t8", null); //
    vectors.put("1qzzfhee", null); //
    vectors.put("A12UEL5L", new Bech32.DecodingResult("a", Bech32Test.EMPTY)); //
    vectors.put("a12uel5l", new Bech32.DecodingResult("a", Bech32Test.EMPTY)); //
    vectors.put("A12UeL5L", null); //
    vectors.put("a12uEl5l", null); //
    vectors.put("an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs", new Bech32.DecodingResult("an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio", Bech32Test.EMPTY)); //
    vectors.put("abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw", new Bech32.DecodingResult("abcdef", DatatypeConverter.parseHexBinary("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))); //
    vectors.put("11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j", new Bech32.DecodingResult("1", DatatypeConverter.parseHexBinary("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"))); //
    vectors.put("x1llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllelz3ww", new Bech32.DecodingResult("x", DatatypeConverter.parseHexBinary("1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F"))); //
    vectors.put("x1lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllrdjtnk", null); //
    vectors.put("split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w", new Bech32.DecodingResult("split", DatatypeConverter.parseHexBinary("18171918161c01100b1d0819171d130d10171d16191c01100b03191d1b1903031d130b190303190d181d01190303190d"))); //
    vectors.put("?1ezyfcl", new Bech32.DecodingResult("?", Bech32Test.EMPTY)); //
    vectors.put(new StringBuilder().appendCodePoint(0x20).append("1nwldj5").toString(), null); //
    vectors.put(new StringBuilder().appendCodePoint(0x7F).append("1axkwrx").toString(), null); //
    vectors.put(new StringBuilder().appendCodePoint(0x80).append("17qyerv").toString(), null); //
    vectors.put(new StringBuilder().appendCodePoint(0x800).append("13psnee").toString(), null); //
    vectors.put(new StringBuilder().appendCodePoint(0x10000).append("1tagmg0").toString(), null); //
    vectors.put("an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx", null); //
    vectors.put("pzry9x0s0muk", null); //
    vectors.put("1pzry9x0s0muk", null); //
    vectors.put("x1b4n0q5v", null); //
    vectors.put("li1dgmt3", null); //
    vectors.put("de1lg7wt" + new StringBuilder().appendCodePoint(0xFF).toString(), null); //
    vectors.put("A1G7SGD8", null); //
    vectors.put(new StringBuilder().appendCodePoint(0x80).append("1eym55h").toString(), null); //
    vectors.put(new StringBuilder().append("de1lg7wt").appendCodePoint(0xFF).toString(), null); //
    vectors.put("bc1q9zpgru", new Bech32.DecodingResult("bc", DatatypeConverter.parseHexBinary("00"))); //
    vectors.put("bc1qqsa7s0f", new Bech32.DecodingResult("bc", DatatypeConverter.parseHexBinary("0000"))); //
    // run the test vectors
    for (final Map.Entry<String, Bech32.DecodingResult> vector : vectors.entrySet()) {
      final Bech32.DecodingResult result = Bech32.decode(vector.getKey());
      if (vector.getValue() == null) {
        Assert.assertNull(result);
      } else {
        Assert.assertEquals(vector.getValue().humanReadablePart, result.humanReadablePart);
        Assert.assertArrayEquals(vector.getValue().data, result.data);
      }
    }
  }

  @Test
  public void test_decode_vectors_segwit() throws Exception {
    final Map<String, Bech32.DecodingResult> vectors = new LinkedHashMap<>();
    vectors.put("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", new Bech32.DecodingResult("bc", DatatypeConverter.parseHexBinary("00751e76e8199196d454941c45d1b3a323f1433bd6"))); //
    vectors.put("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4".toLowerCase(Locale.ROOT), new Bech32.DecodingResult("bc", DatatypeConverter.parseHexBinary("00751e76e8199196d454941c45d1b3a323f1433bd6"))); //
    vectors.put("bC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", null); //
    vectors.put("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", new Bech32.DecodingResult("tb", DatatypeConverter.parseHexBinary("001863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"))); //
    vectors.put("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx", new Bech32.DecodingResult("bc", DatatypeConverter.parseHexBinary("01751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"))); //
    vectors.put("BC1SW50QA3JX3S", new Bech32.DecodingResult("bc", DatatypeConverter.parseHexBinary("10751e"))); //
    vectors.put("bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj", new Bech32.DecodingResult("bc", DatatypeConverter.parseHexBinary("02751e76e8199196d454941c45d1b3a323"))); //
    vectors.put("tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy", new Bech32.DecodingResult("tb", DatatypeConverter.parseHexBinary("00000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"))); //
    vectors.put("tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty", new Bech32.DecodingResult("tc", DatatypeConverter.parseHexBinary("00751e76e8199196d454941c45d1b3a323f1433bd6"))); //
    vectors.put("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", null); //
    vectors.put("BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2", new Bech32.DecodingResult("bc", DatatypeConverter.parseHexBinary("11751e76e8199196d454941c45d1b3a323f1433bd6"))); //
    vectors.put("bc1rw5uspcuh", new Bech32.DecodingResult("bc", DatatypeConverter.parseHexBinary("0375"))); //
    vectors.put("bc1qqqglchaj", new Bech32.DecodingResult("bc", DatatypeConverter.parseHexBinary("0000"))); //
    vectors.put("bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90", new Bech32.DecodingResult("bc", DatatypeConverter.parseHexBinary("0F751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd675"))); //
    vectors.put("BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P", new Bech32.DecodingResult("bc", DatatypeConverter.parseHexBinary("001d1e76e8199196d454941c45d1b3a323"))); //
    vectors.put("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7", null); //
    vectors.put("Tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7", null); //
    vectors.put("bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du", new Bech32.DecodingResult("bc", DatatypeConverter.parseHexBinary("02"))); // shorter than might be expected because 5 to 8 conversion fails due to "zero padding of more than 4 bits"
    vectors.put("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv", new Bech32.DecodingResult("tb", DatatypeConverter.parseHexBinary("00"))); // shorter than might be expected because 5 to 8 conversion fails due to "non-zero padding"
    vectors.put("bc1gmk9yu", new Bech32.DecodingResult("bc", Bech32Test.EMPTY)); //
    // run the test vectors
    for (final Map.Entry<String, Bech32.DecodingResult> vector : vectors.entrySet()) {
      final Bech32.DecodingResult result = Bech32.decode(vector.getKey());
      if (vector.getValue() == null) {
        Assert.assertNull(result);
      } else {
        byte[] data = Bech32Test.EMPTY;
        if (result.data.length != 0) {
          final byte[] converted = Bech32.convert(result.data, 1, result.data.length - 1, 5, 8);
          if (null != converted) {
            data = new byte[1 + converted.length];
            data[0] = result.data[0];
            System.arraycopy(converted, 0, data, 1, converted.length);
          } else {
            data = new byte[] { result.data[0] };
          }
        }
        Assert.assertEquals(vector.getValue().humanReadablePart, result.humanReadablePart);
        Assert.assertArrayEquals(vector.getValue().data, data);
      }
    }
  }

  @Test
  public void test_encode_vectors() throws Exception {
    final Object[][] vectors = { //
        { null, null, null }, //
        { null, Bech32Test.EMPTY, null }, //
        { "", null, null }, //
        { "", Bech32Test.EMPTY, null }, //
        { "", new byte[] { 0 }, null }, //
        { " ", new byte[] { 0 }, null }, //
        { "a", Bech32Test.EMPTY, "a12uel5l" }, //
        { "A", Bech32Test.EMPTY, "a12uel5l" }, //
        { "A", new byte[] { -128 }, null }, //
        { "A", new byte[] { -1 }, null }, //
        { "A", new byte[] { 32 }, null }, //
        { "A", new byte[83], null }, //
        { "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio", Bech32Test.EMPTY, "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs" }, //
        { "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio", new byte[82], null }, //
        { "abcdef", DatatypeConverter.parseHexBinary("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw" }, //
        { "1", DatatypeConverter.parseHexBinary("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"), "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j" }, //
        { "x", DatatypeConverter.parseHexBinary("1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F"), "x1llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllelz3ww" }, //
        { "split", DatatypeConverter.parseHexBinary("18171918161c01100b1d0819171d130d10171d16191c01100b03191d1b1903031d130b190303190d181d01190303190d"), "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w" }, //
        { "?", Bech32Test.EMPTY, "?1ezyfcl" }, //
        { "bc", Bech32Test.EMPTY, "bc1gmk9yu" }, //
        { "tb", Bech32Test.EMPTY, "tb1cy0q7p" }, //
        { new StringBuilder().appendCodePoint(0x20).toString(), Bech32Test.EMPTY, null }, //
        { new StringBuilder().appendCodePoint(0x7F).toString(), Bech32Test.EMPTY, null }, //
        { new StringBuilder().appendCodePoint(0x80).toString(), Bech32Test.EMPTY, null }, //
        { new StringBuilder().appendCodePoint(0x800).toString(), Bech32Test.EMPTY, null }, //
        { new StringBuilder().appendCodePoint(0x10000).toString(), Bech32Test.EMPTY, null }, //
        { "\ud800\udc00", Bech32Test.EMPTY, null }, //
        { "b\u200dc", Bech32Test.EMPTY, null }, //
        { "\u0430", Bech32Test.EMPTY, null }, //
        { "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio", Bech32Test.EMPTY, null }, //
        { new StringBuilder().appendCodePoint(0x80).append("1eym55h").toString(), Bech32Test.EMPTY, null }, //
    };
    // run the test vectors
    for (final Object[] vector : vectors) {
      final String result = Bech32.encode((String) vector[0], (byte[]) vector[1]);
      Assert.assertEquals(vector[2], result);
      // test the test vector
      final DecodingResult decoded = Bech32.decode(result);
      if (null == decoded) {
        Assert.assertNull(vector[2]);
      } else {
        Assert.assertEquals(decoded.humanReadablePart, ((String) vector[0]).toLowerCase(Locale.ROOT));
        Assert.assertArrayEquals(decoded.data, (byte[]) vector[1]);
      }
    }
  }

  @Test
  public void test_encode_vectors_segwit() throws Exception {
    final Object[][] vectors = { //
        { "bc", 0, Bech32.convert(DatatypeConverter.parseHexBinary("751e76e8199196d454941c45d1b3a323f1433bd6"), 0, 20, 8, 5), "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4".toLowerCase(Locale.ROOT) }, //
        { "Bc", 0, Bech32.convert(DatatypeConverter.parseHexBinary("751e76e8199196d454941c45d1b3a323f1433bd6"), 0, 20, 8, 5), "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4".toLowerCase(Locale.ROOT) }, //
        { "bC", 0, Bech32.convert(DatatypeConverter.parseHexBinary("751e76e8199196d454941c45d1b3a323f1433bd6"), 0, 20, 8, 5), "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4".toLowerCase(Locale.ROOT) }, //
        { "BC", 0, Bech32.convert(DatatypeConverter.parseHexBinary("751e76e8199196d454941c45d1b3a323f1433bd6"), 0, 20, 8, 5), "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4".toLowerCase(Locale.ROOT) }, //
        { "tb", 0, Bech32.convert(DatatypeConverter.parseHexBinary("1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"), 0, 32, 8, 5), "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7" }, //
        { "bc", 1, Bech32.convert(DatatypeConverter.parseHexBinary("751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"), 0, 40, 8, 5), "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx" }, //
        { "bc", 16, Bech32.convert(DatatypeConverter.parseHexBinary("751e"), 0, 2, 8, 5), "BC1SW50QA3JX3S".toLowerCase(Locale.ROOT) }, //
        { "bc", 2, Bech32.convert(DatatypeConverter.parseHexBinary("751e76e8199196d454941c45d1b3a323"), 0, 16, 8, 5), "bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj" }, //
        { "tb", 0, Bech32.convert(DatatypeConverter.parseHexBinary("000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"), 0, 32, 8, 5), "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy" }, //
        { "tc", 0, Bech32.convert(DatatypeConverter.parseHexBinary("751e76e8199196d454941c45d1b3a323f1433bd6"), 0, 20, 8, 5), "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty" }, //
        { "bc", 17, Bech32.convert(DatatypeConverter.parseHexBinary("751e76e8199196d454941c45d1b3a323f1433bd6"), 0, 20, 8, 5), "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2".toLowerCase(Locale.ROOT) }, //
        { "bc", 3, Bech32.convert(DatatypeConverter.parseHexBinary("75"), 0, 1, 8, 5), "bc1rw5uspcuh" }, //
        { "bc", 0, Bech32.convert(DatatypeConverter.parseHexBinary("00"), 0, 1, 8, 5), "bc1qqqglchaj" }, //
        { "bc", 0, new byte[] { 0 }, "bc1qqsa7s0f" }, //
        { "bc", 15, Bech32.convert(DatatypeConverter.parseHexBinary("751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd675"), 0, 41, 8, 5), "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90" }, //
        { "bc", 0, Bech32.convert(DatatypeConverter.parseHexBinary("1d1e76e8199196d454941c45d1b3a323"), 0, 16, 8, 5), "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P".toLowerCase(Locale.ROOT) }, //
        { "tb", 0, Bech32.convert(DatatypeConverter.parseHexBinary("1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"), 0, 32, 8, 5), "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7".toLowerCase(Locale.ROOT) }, //
    };
    // run the test vectors
    for (final Object[] vector : vectors) {
      final byte witnessVersion = ((Integer) vector[1]).byteValue();
      final byte[] witnessProgram = (byte[]) vector[2];
      final byte[] temp = new byte[1 + witnessProgram.length];
      temp[0] = witnessVersion;
      System.arraycopy(witnessProgram, 0, temp, 1, witnessProgram.length);
      final String result = Bech32.encode((String) vector[0], temp);
      Assert.assertEquals(vector[3], result);
      // test the test vector
      final DecodingResult decoded = Bech32.decode(result);
      Assert.assertEquals(decoded.humanReadablePart, ((String) vector[0]).toLowerCase(Locale.ROOT));
      Assert.assertArrayEquals(decoded.data, temp);
    }
  }
}
