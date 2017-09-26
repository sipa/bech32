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

import java.util.Arrays;

/**
 * https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
 * https://github.com/satoshilabs/slips/blob/master/slip-0173.md
 */
public class SegwitAddress {
  public static final class DecodingResult {
    public final String humanReadablePart;
    public final byte witnessVersion;
    public final byte[] witnessProgram;

    DecodingResult(final String humanReadablePart, final byte witnessVersion, final byte[] witnessProgram) {
      this.humanReadablePart = humanReadablePart;
      this.witnessVersion = witnessVersion;
      this.witnessProgram = witnessProgram;
    }

    @Override
    public String toString() {
      return "humanReadablePart=" + this.humanReadablePart + ", witnessVersion=" + this.witnessVersion + ", witnessProgram=" + Arrays.toString(this.witnessProgram);
    }
  }

  /**
   * @param address
   * @return If decoding fails, null.
   *         Otherwise, a SegwitAddress.DecodingResult containing the decoded human readable part, witness version, and witness program.
   *         Users of this decoder must verify that the returned human readable part is valid for their application.
   *         Note that the witness version output from this decoder will be in the range [0, 16].
   *         WARNING: From https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki:
   *         "Implementations should take special care when converting the address to a scriptPubkey, where witness version n is stored
   *         as OP_n. OP_0 is encoded as 0x00, but OP_1 through OP_16 are encoded as 0x51 though 0x60 (81 to 96 in decimal). If a
   *         bech32 address is converted to an incorrect scriptPubKey the result will likely be either unspendable or insecure."
   */
  public static DecodingResult decode(final String address) {
    final Bech32.DecodingResult decoded = Bech32.decode(address);
    if (null == decoded) {
      return null; // failure
    }
    if ((decoded.data.length < 1) || (decoded.data[0] < 0) || (decoded.data[0] > 16)) {
      return null; // failure
    }
    final byte[] program = Bech32.convert(decoded.data, 1, decoded.data.length - 1, 5, 8);
    if ((null == program) || (program.length < 2) || (program.length > 40)) {
      return null; // failure
    }
    if ((decoded.data[0] == 0) && (program.length != 20) && (program.length != 32)) {
      return null; // failure
    }
    return new DecodingResult(decoded.humanReadablePart, decoded.data[0], program);
  }

  /**
   * @param humanReadablePart application specific human readable part of the address
   * @param witnessVersion must be in the range [0, 16], note that these values are NOT "OP_n" values
   * @param witnessProgram must be [2, 40] bytes long and must be either 20 or 32 bytes long when witnessVersion is zero
   * @return If encoding fails, null. Otherwise, a Bech32 encoded segwit address.
   */
  public static String encode(final String humanReadablePart, final byte witnessVersion, final byte[] witnessProgram) {
    if ((witnessVersion < 0) || (witnessVersion > 16)) {
      return null; // failure
    }
    if ((null == witnessProgram) || (witnessProgram.length < 2) || (witnessProgram.length > 40)) {
      return null; // failure
    }
    if ((witnessVersion == 0) && (witnessProgram.length != 20) && (witnessProgram.length != 32)) {
      return null; // failure
    }
    final byte[] program = Bech32.convert(witnessProgram, 0, witnessProgram.length, 8, 5);
    final byte[] data = new byte[1 + program.length];
    data[0] = witnessVersion;
    System.arraycopy(program, 0, data, 1, program.length);
    return Bech32.encode(humanReadablePart, data);
  }
}
