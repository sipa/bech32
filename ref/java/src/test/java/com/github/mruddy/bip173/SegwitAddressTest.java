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
import com.github.mruddy.bip173.SegwitAddress.DecodingResult;

public class SegwitAddressTest {
  private static final byte[] EMPTY = {};

  @Test
  public void test_decode_vectors() throws Exception {
    final Map<String, SegwitAddress.DecodingResult> vectors = new LinkedHashMap<>();
    vectors.put(null, null);
    vectors.put("", null);
    vectors.put(" ", null);
    vectors.put("a", null);
    vectors.put("0", null);
    vectors.put("1", null);
    vectors.put("123456", null);
    vectors.put("1234567", null);
    vectors.put("12345678", null);
    vectors.put("012345", null);
    vectors.put("0123456", null);
    vectors.put("01234567", null);
    vectors.put("10a06t8", null);
    vectors.put("1qzzfhee", null);
    vectors.put("A12UEL5L", null);
    vectors.put("a12uel5l", null);
    vectors.put("A12UeL5L", null);
    vectors.put("a12uEl5l", null);
    vectors.put("an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs", null);
    vectors.put("abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw", null);
    vectors.put("11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j", null);
    vectors.put("x1llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllelz3ww", null);
    vectors.put("x1lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllrdjtnk", null);
    vectors.put("split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w", null);
    vectors.put("?1ezyfcl", null);
    vectors.put(new StringBuilder().appendCodePoint(0x20).append("1nwldj5").toString(), null);
    vectors.put(new StringBuilder().appendCodePoint(0x7F).append("1axkwrx").toString(), null);
    vectors.put(new StringBuilder().appendCodePoint(0x80).append("17qyerv").toString(), null);
    vectors.put(new StringBuilder().appendCodePoint(0x800).append("13psnee").toString(), null);
    vectors.put(new StringBuilder().appendCodePoint(0x10000).append("1tagmg0").toString(), null);
    vectors.put("an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx", null);
    vectors.put("pzry9x0s0muk", null);
    vectors.put("1pzry9x0s0muk", null);
    vectors.put("x1b4n0q5v", null);
    vectors.put("li1dgmt3", null);
    vectors.put("A1G7SGD8", null);
    vectors.put(new StringBuilder().appendCodePoint(0x80).append("1eym55h").toString(), null);
    vectors.put(new StringBuilder().append("de1lg7wt").appendCodePoint(0xFF).toString(), null);
    vectors.put("bc1q9zpgru", null);
    vectors.put("bc1qqsa7s0f", null);
    vectors.put("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", new SegwitAddress.DecodingResult("bc", (byte) 0, DatatypeConverter.parseHexBinary("751e76e8199196d454941c45d1b3a323f1433bd6")));
    vectors.put("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4".toLowerCase(Locale.ROOT), new SegwitAddress.DecodingResult("bc", (byte) 0, DatatypeConverter.parseHexBinary("751e76e8199196d454941c45d1b3a323f1433bd6")));
    vectors.put("bC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", null);
    vectors.put("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", new SegwitAddress.DecodingResult("tb", (byte) 0, DatatypeConverter.parseHexBinary("1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262")));
    vectors.put("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx", new SegwitAddress.DecodingResult("bc", (byte) 1, DatatypeConverter.parseHexBinary("751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6")));
    vectors.put("BC1SW50QA3JX3S", new SegwitAddress.DecodingResult("bc", (byte) 16, DatatypeConverter.parseHexBinary("751e")));
    vectors.put("bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj", new SegwitAddress.DecodingResult("bc", (byte) 2, DatatypeConverter.parseHexBinary("751e76e8199196d454941c45d1b3a323")));
    vectors.put("tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy", new SegwitAddress.DecodingResult("tb", (byte) 0, DatatypeConverter.parseHexBinary("000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433")));
    vectors.put("tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty", new SegwitAddress.DecodingResult("tc", (byte) 0, DatatypeConverter.parseHexBinary("751e76e8199196d454941c45d1b3a323f1433bd6")));
    vectors.put("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", null);
    vectors.put("BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2", null);
    vectors.put("bc1rw5uspcuh", null);
    vectors.put("bc1qqqglchaj", null);
    vectors.put("bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90", null);
    vectors.put("BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P", null);
    vectors.put("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7", null);
    vectors.put("Tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7", null);
    vectors.put("bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du", null);
    vectors.put("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv", null);
    vectors.put("bc1gmk9yu", null);
    // run the test vectors
    for (final Map.Entry<String, SegwitAddress.DecodingResult> vector : vectors.entrySet()) {
      final SegwitAddress.DecodingResult result = SegwitAddress.decode(vector.getKey());
      if (vector.getValue() == null) {
        Assert.assertNull(result);
      } else {
        Assert.assertEquals(vector.getValue().humanReadablePart, result.humanReadablePart);
        Assert.assertEquals(vector.getValue().witnessVersion, result.witnessVersion);
        Assert.assertArrayEquals(vector.getValue().witnessProgram, result.witnessProgram);
      }
    }
  }

  @Test
  public void test_encode_vectors() throws Exception {
    final Object[][] vectors = { //
        { null, 0, null, null }, //
        { null, 0, SegwitAddressTest.EMPTY, null }, //
        { "", 0, null, null }, //
        { "", 0, SegwitAddressTest.EMPTY, null }, //
        { "", 0, new byte[] { 0 }, null }, //
        { " ", 0, new byte[] { 0 }, null }, //
        { "a", 0, SegwitAddressTest.EMPTY, null }, //
        { "A", 0, SegwitAddressTest.EMPTY, null }, //
        { "A", 0, new byte[] { -128 }, null }, //
        { "A", 0, new byte[] { -1 }, null }, //
        { "A", 0, new byte[] { 32 }, null }, //
        { "A", 0, new byte[83], null }, //
        { "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio", 0, SegwitAddressTest.EMPTY, null }, //
        { "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio", 0, new byte[82], null }, //
        { "abcdef", -1, DatatypeConverter.parseHexBinary("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), null }, //
        { "abcdef", 0, DatatypeConverter.parseHexBinary("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), "abcdef1qqqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0saqd9wh" }, //
        { "abcdef", 16, DatatypeConverter.parseHexBinary("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), "abcdef1sqqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0sp5h8mm" }, //
        { "abcdef", 17, DatatypeConverter.parseHexBinary("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), null }, //
        { "1", 0, DatatypeConverter.parseHexBinary("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"), null }, //
        { "1", 1, DatatypeConverter.parseHexBinary("00000000000000000000000000000000000000000000000000000000000000000000000000000000"), "11pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqha9xzw" }, //
        { "1", 1, DatatypeConverter.parseHexBinary("0000000000000000000000000000000000000000000000000000000000000000"), "11pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq8p2umf" }, //
        { "x", 0, DatatypeConverter.parseHexBinary("1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F"), null }, //
        { "split", 0, DatatypeConverter.parseHexBinary("18171918161c01100b1d0819171d130d10171d16191c01100b03191d1b1903031d130b190303190d181d01190303190d"), null }, //
        { "?", 0, SegwitAddressTest.EMPTY, null }, //
        { "bc", 0, SegwitAddressTest.EMPTY, null }, //
        { "tb", 0, SegwitAddressTest.EMPTY, null }, //
        { new StringBuilder().appendCodePoint(0x20).toString(), 0, SegwitAddressTest.EMPTY, null }, //
        { new StringBuilder().appendCodePoint(0x7F).toString(), 0, SegwitAddressTest.EMPTY, null }, //
        { new StringBuilder().appendCodePoint(0x80).toString(), 0, SegwitAddressTest.EMPTY, null }, //
        { new StringBuilder().appendCodePoint(0x800).toString(), 0, SegwitAddressTest.EMPTY, null }, //
        { new StringBuilder().appendCodePoint(0x10000).toString(), 0, SegwitAddressTest.EMPTY, null }, //
        { "\ud800\udc00", 0, SegwitAddressTest.EMPTY, null }, //
        { "b\u200dc", 0, SegwitAddressTest.EMPTY, null }, //
        { "\u0430", 0, SegwitAddressTest.EMPTY, null }, //
        { "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio", 0, SegwitAddressTest.EMPTY, null }, //
        { new StringBuilder().appendCodePoint(0x80).append("1eym55h").toString(), 0, SegwitAddressTest.EMPTY, null }, //
        { "bc", 0, DatatypeConverter.parseHexBinary("751e76e8199196d454941c45d1b3a323f1433bd6"), "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4".toLowerCase(Locale.ROOT) }, //
        { "Bc", 0, DatatypeConverter.parseHexBinary("751e76e8199196d454941c45d1b3a323f1433bd6"), "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4".toLowerCase(Locale.ROOT) }, //
        { "bC", 0, DatatypeConverter.parseHexBinary("751e76e8199196d454941c45d1b3a323f1433bd6"), "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4".toLowerCase(Locale.ROOT) }, //
        { "BC", 0, DatatypeConverter.parseHexBinary("751e76e8199196d454941c45d1b3a323f1433bd6"), "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4".toLowerCase(Locale.ROOT) }, //
        { "tb", 0, DatatypeConverter.parseHexBinary("1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"), "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7" }, //
        { "bc", 1, DatatypeConverter.parseHexBinary("751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"), "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx" }, //
        { "bc", 16, DatatypeConverter.parseHexBinary("751e"), "BC1SW50QA3JX3S".toLowerCase(Locale.ROOT) }, //
        { "bc", 2, DatatypeConverter.parseHexBinary("751e76e8199196d454941c45d1b3a323"), "bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj" }, //
        { "tb", 0, DatatypeConverter.parseHexBinary("000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"), "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy" }, //
        { "tc", 0, DatatypeConverter.parseHexBinary("751e76e8199196d454941c45d1b3a323f1433bd6"), "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty" }, //
        { "bc", 17, DatatypeConverter.parseHexBinary("751e76e8199196d454941c45d1b3a323f1433bd6"), null }, //
        { "bc", 3, DatatypeConverter.parseHexBinary("75"), null }, // bc1rw5uspcuh
        { "bc", 0, DatatypeConverter.parseHexBinary("00"), null }, // bc1qqqglchaj
        { "bc", 0, new byte[] { 0 }, null }, // bc1qqsa7s0f
        { "bc", 15, DatatypeConverter.parseHexBinary("751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd675"), null }, // bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90
        { "bc", 0, DatatypeConverter.parseHexBinary("1d1e76e8199196d454941c45d1b3a323"), null }, // "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P".toLowerCase(Locale.ROOT)
        { "tb", 0, DatatypeConverter.parseHexBinary("1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"), "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7".toLowerCase(Locale.ROOT) }, //
    };
    // run the test vectors
    for (final Object[] vector : vectors) {
      final String result = SegwitAddress.encode((String) vector[0], ((Integer) vector[1]).byteValue(), (byte[]) vector[2]);
      Assert.assertEquals(vector[3], result);
      // test the test vector
      final DecodingResult decoded = SegwitAddress.decode(result);
      if (null == decoded) {
        Assert.assertNull(vector[3]);
      } else {
        Assert.assertEquals(decoded.humanReadablePart, ((String) vector[0]).toLowerCase(Locale.ROOT));
        Assert.assertEquals(decoded.witnessVersion, ((Integer) vector[1]).byteValue());
        Assert.assertArrayEquals(decoded.witnessProgram, (byte[]) vector[2]);
      }
    }
  }
}
