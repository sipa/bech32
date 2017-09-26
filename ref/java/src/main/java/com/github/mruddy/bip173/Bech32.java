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

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
 * https://github.com/satoshilabs/slips/blob/master/slip-0173.md
 */
public final class Bech32 {
  public static final class DecodingResult {
    public final String humanReadablePart;
    public final byte[] data;

    DecodingResult(final String humanReadablePart, final byte[] data) {
      this.humanReadablePart = humanReadablePart;
      this.data = data;
    }

    @Override
    public String toString() {
      return "humanReadablePart=" + this.humanReadablePart + ", data=" + Arrays.toString(this.data);
    }
  }

  private static final int MIN_BECH32_LENGTH = 1 + 1 + 6;
  private static final int MAX_BECH32_LENGTH = 90;
  private static final int MIN_HRP_LENGTH = 1;
  private static final int MAX_HRP_LENGTH = 83;
  private static final int SEPARATOR = '1';
  private static final byte[] CHARSET = { //
      'q', 'p', 'z', 'r', 'y', '9', 'x', '8', //
      'g', 'f', '2', 't', 'v', 'd', 'w', '0', //
      's', '3', 'j', 'n', '5', '4', 'k', 'h', //
      'c', 'e', '6', 'm', 'u', 'a', '7', 'l', //
  };
  private static final byte[] CHARSET_REVERSE = { //
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, //
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, //
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, //
      15, -1, 10, 17, 21, 20, 26, 30, 7, 5, -1, -1, -1, -1, -1, -1, //
      -1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1, //
      1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1, //
      -1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1, //
      1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1, //
  };
  private static final byte[] CHECKSUM = { 0, 0, 0, 0, 0, 0, };

  private static byte[] checksum(final byte[] hrp, final byte[] data) {
    final int polymod = Bech32.polymod(Bech32.expand(hrp), data, Bech32.CHECKSUM) ^ 1;
    return new byte[] { //
        (byte) ((polymod >>> 25) & 0x1f), //
        (byte) ((polymod >>> 20) & 0x1f), //
        (byte) ((polymod >>> 15) & 0x1f), //
        (byte) ((polymod >>> 10) & 0x1f), //
        (byte) ((polymod >>> 5) & 0x1f), //
        (byte) ((polymod >>> 0) & 0x1f), //
    };
  }

  /**
   * @param input an array of either 8-bit (base 2^8), or 5-bit (base 2^5), bytes
   * @param offset start processing at this index into the input
   * @param count process this many bytes of the input
   * @param fromBase must be 8 when toBase is 5, or 5 when toBase is 8
   * @param toBase must be 5 when fromBase is 8, or 8 when fromBase is 5
   * @return If when converting from 5 to 8 and invalid padding is encountered, null.
   *         Otherwise an array of bytes where each byte has been converted from fromBase to toBase.
   */
  public static byte[] convert(final byte[] input, final int offset, final int count, final int fromBase, final int toBase) {
    if ((offset < 0) || (count < 0) || (offset > (input.length - count))) {
      throw new IndexOutOfBoundsException();
    }
    if (!((fromBase == 8) && (toBase == 5)) && !((fromBase == 5) && (toBase == 8))) {
      throw new IllegalArgumentException("invalid fromBase toBase combination");
    }
    final int toMask = (1 << toBase) - 1;
    final boolean pad = ((fromBase == 8) && (toBase == 5)); // BIP173 specific rule
    final byte[] result = new byte[((count * fromBase) + ((pad ? 1 : 0) * (toBase - 1))) / toBase];
    int resultIndex = 0;
    int bits = 0;
    int bitsAvailable = 0;
    for (int i = offset; i < (offset + count); i++) {
      final int temp = input[i] & 0xFF;
      bits = (bits << fromBase) | temp;
      bitsAvailable += fromBase;
      while (bitsAvailable >= toBase) {
        bitsAvailable -= toBase;
        result[resultIndex++] = (byte) ((bits >>> bitsAvailable) & toMask);
      }
    }
    // BIP-0173 specific rules - note that this method is intended to be used to invert its prior output
    // (i.e.- go from 8-bit bytes, to 5-bit bytes, back to the exact original 8-bit bytes -- in other
    // words, to go from base 2^8, to base 2^5, back to base 2^8).
    if (bitsAvailable != 0) {
      if (pad) { // save the bits with zero padding
        result[resultIndex++] = (byte) ((bits << (toBase - bitsAvailable)) & toMask);
      } else { // discard the bits, but check for invalid conditions first
        if ((((bits << (toBase - bitsAvailable)) & toMask) != 0) || (bitsAvailable >= fromBase)) {
          return null;
        }
      }
    }
    return result;
  }

  /**
   * @param bech32 A Bech32 encoded String
   * @return If decoding fails, null.
   *         Otherwise, a Bech32.DecodingResult containing the decoded human readable part and data (with the data being 5-bit, base 2^5, bytes).
   */
  public static DecodingResult decode(final String bech32) {
    if ((null == bech32) || (bech32.length() < Bech32.MIN_BECH32_LENGTH) || (bech32.length() > Bech32.MAX_BECH32_LENGTH)) {
      return null; // failure
    }
    int seperatorIndex = -1;
    boolean hasLower = false;
    boolean hasUpper = false;
    for (int i = 0; i < bech32.length(); i++) {
      final int c = bech32.charAt(i); // do widening primitive conversion once
      if ((c < 33) || (c > 126)) {
        return null; // failure
      }
      hasLower |= (c >= 'a') && (c <= 'z');
      hasUpper |= (c >= 'A') && (c <= 'Z');
      if (hasLower && hasUpper) {
        return null; // failure
      }
      if (Bech32.SEPARATOR == c) {
        seperatorIndex = i; // the last one found is the separator
      }
    }
    if ((seperatorIndex < 1) || (seperatorIndex > (bech32.length() - Bech32.CHECKSUM.length - 1))) {
      return null; // failure
    }
    // process the human readable part
    final byte[] hrp = new byte[seperatorIndex];
    for (int i = 0; i < hrp.length; i++) {
      int c = bech32.charAt(i);
      if ((c >= 'A') && (c <= 'Z')) {
        c |= 0x20; // to ensure that the checksum is computed over the lower case form
      }
      hrp[i] = (byte) c;
    }
    // process the data part
    final byte[] data = new byte[bech32.length() - Bech32.CHECKSUM.length - seperatorIndex - 1];
    for (int i = 0; i < data.length; i++) {
      final int c = bech32.charAt(seperatorIndex + 1 + i);
      final byte lookup = Bech32.CHARSET_REVERSE[c];
      if (-1 == lookup) {
        return null; // failure
      }
      data[i] = lookup;
    }
    // process the checksum
    final byte[] checksum = new byte[Bech32.CHECKSUM.length];
    for (int i = 0; i < checksum.length; i++) {
      final int c = bech32.charAt((bech32.length() - Bech32.CHECKSUM.length) + i);
      final byte lookup = Bech32.CHARSET_REVERSE[c];
      if (-1 == lookup) {
        return null; // failure
      }
      checksum[i] = lookup;
    }
    if (Bech32.verify(hrp, data, checksum)) {
      return new DecodingResult(new String(hrp, StandardCharsets.US_ASCII), data);
    }
    return null; // failure
  }

  /**
   * @param humanReadablePart
   * @param data all bytes must be in the range [0, 31]
   * @return If encoding fails, null. Otherwise, a valid Bech32 encoded String.
   */
  public static String encode(final String humanReadablePart, final byte[] data) {
    if ((null == humanReadablePart) || (humanReadablePart.length() < Bech32.MIN_HRP_LENGTH) || (humanReadablePart.length() > Bech32.MAX_HRP_LENGTH)) {
      return null; // failure
    }
    if ((null == data) || (data.length > (Bech32.MAX_BECH32_LENGTH - 6 - 1 - humanReadablePart.length()))) {
      return null; // failure
    }
    final byte[] hrp = new byte[humanReadablePart.length()];
    for (int i = 0; i < hrp.length; i++) {
      int c = humanReadablePart.charAt(i); // do widening primitive conversion once
      if ((c < 33) || (c > 126)) {
        return null; // failure
      }
      if ((c >= 'A') && (c <= 'Z')) {
        c |= 0x20; // ensure the encoded result is lower case and that the checksum is computed over the lower case form
      }
      hrp[i] = (byte) c;
    }
    for (final byte element : data) {
      if ((element & ~0x1F) != 0) {
        return null; // failure
      }
    }
    final byte[] checksum = Bech32.checksum(hrp, data);
    final byte[] result = new byte[hrp.length + 1 + data.length + checksum.length];
    System.arraycopy(hrp, 0, result, 0, hrp.length);
    result[hrp.length] = Bech32.SEPARATOR;
    System.arraycopy(data, 0, result, hrp.length + 1, data.length);
    System.arraycopy(checksum, 0, result, result.length - checksum.length, checksum.length);
    for (int i = hrp.length + 1; i < result.length; i++) {
      result[i] = Bech32.CHARSET[result[i]];
    }
    return new String(result, StandardCharsets.US_ASCII);
  }

  private static byte[] expand(final byte[] hrp) {
    final byte[] result = new byte[(hrp.length * 2) + 1];
    for (int i = 0; i < hrp.length; i++) {
      final int temp = hrp[i] & 0xFF;
      result[i] = (byte) (temp >>> 5); // top 3 bits of the byte
      result[hrp.length + 1 + i] = (byte) (temp & 0x1F); // bottom 5 bits of the byte
    }
    return result;
  }

  /**
   * @param values operates on bytes in the range [0, 31] (5-bit values)
   * @return
   */
  private static int polymod(final byte[]... values) {
    int result = 1; // 6, 5-bit values are packed together as a single 30-bit integer
    for (final byte[] bytes : values) {
      for (final byte b : bytes) {
        final int result0 = result >>> 25;
        result = ((result & 0x1ffffff) << 5) ^ //
            b ^ //
            (-((result0 >>> 0) & 1) & 0x3b6a57b2) ^ // note: (value XOR 0) = value
            (-((result0 >>> 1) & 1) & 0x26508e6d) ^ //
            (-((result0 >>> 2) & 1) & 0x1ea119fa) ^ //
            (-((result0 >>> 3) & 1) & 0x3d4233dd) ^ //
            (-((result0 >>> 4) & 1) & 0x2a1462b3);
      }
    }
    return result;
  }

  private static boolean verify(final byte[] hrp, final byte[] data, final byte[] checksum) {
    return Bech32.polymod(Bech32.expand(hrp), data, checksum) == 1;
  }

  private Bech32() {
    throw new AssertionError("suppress default constructor for noninstantiability");
  }
}
