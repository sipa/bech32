/* Copyright (c) 2018 Coinomi Ltd
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package org.bech32;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class SegwitAddress {
    public static class SegwitAddressException extends Exception {
        SegwitAddressException(Exception e) {
            super(e);
        }
        SegwitAddressException(String s) {
            super(s);
        }
    }

    public static class SegwitAddressData {
        public final byte version;
        public final byte[] program;

        public SegwitAddressData(final int version, final byte[] program)
                throws SegwitAddressException {
            this.version = (byte) (version & 0xff);
            this.program = program;
            verify(this);
        }
    }

    private static byte[] convertBits(final byte[] in, final int inStart, final int inLen,
                                      final int fromBits, final int toBits, final boolean pad)
            throws SegwitAddressException {
        int acc = 0;
        int bits = 0;
        ByteArrayOutputStream out = new ByteArrayOutputStream(64);
        final int maxv = (1 << toBits) - 1;
        final int max_acc = (1 << (fromBits + toBits - 1)) - 1;
        for (int i = 0; i < inLen; i++) {
            int value = in[i + inStart] & 0xff;
            if ((value >>> fromBits) != 0) {
                throw new SegwitAddressException(String.format(
                        "Input value '%X' exceeds '%d' bit size", value, fromBits));
            }
            acc = ((acc << fromBits) | value) & max_acc;
            bits += fromBits;
            while (bits >= toBits) {
                bits -= toBits;
                out.write((acc >>> bits) & maxv);
            }
        }
        if (pad) {
            if (bits > 0) out.write((acc << (toBits - bits)) & maxv);
        } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) != 0) {
            throw new SegwitAddressException("Could not convert bits, invalid padding");
        }
        return out.toByteArray();
    }

    /** Decode a SegWit address. */
    public static SegwitAddressData decode(final String hrp, final String addr)
            throws SegwitAddressException {
        Bech32.Bech32Data dec;
        try {
            dec = Bech32.decode(addr);
        } catch (Bech32.Bech32Exception e) {
            throw new SegwitAddressException(e);
        }
        if (dec.hrp.compareToIgnoreCase(hrp) != 0) {
            throw new SegwitAddressException(String.format(
                    "Human-readable part expected '%s' but found '%s'", hrp, dec.hrp));
        }
        if (dec.values.length < 1) throw new SegwitAddressException("Zero data found");
        // Skip the version byte and convert the rest of the decoded bytes
        byte[] conv = convertBits(dec.values, 1, dec.values.length - 1, 5, 8, false);

        return new SegwitAddressData(dec.values[0], conv);
    }

    /** Encode a SegWit address. */
    public static String encode(final String hrp, final int witver, final byte[] witprog)
            throws SegwitAddressException {
        ByteArrayOutputStream enc = new ByteArrayOutputStream(64 + 1);
        enc.write(witver);
        String ret;
        try {
            enc.write(convertBits(witprog, 0, witprog.length, 8, 5, true));
            ret = Bech32.encode(hrp, enc.toByteArray());
        } catch (Bech32.Bech32Exception | IOException e) {
            throw new SegwitAddressException(e);
        }
        decode(hrp, ret);
        return ret;
    }

    /**
     * Runs the SegWit address verification
     * @throws SegwitAddressException on error
     */
    public static void verify(SegwitAddressData data) throws SegwitAddressException {
        if (data.version > 16) {
            throw new SegwitAddressException("Invalid script version");
        }
        if (data.program.length < 2 || data.program.length > 40) {
            throw new SegwitAddressException("Invalid length");
        }
        // Check script length for version 0
        if (data.version == 0 && data.program.length != 20 && data.program.length != 32) {
            throw new SegwitAddressException("Invalid length for address version 0");
        }
    }

    public static byte[] toScriptpubkey(SegwitAddressData data) {
        ByteArrayOutputStream pubkey = new ByteArrayOutputStream(40 + 1);
        int v = data.version;
        // OP_0 is encoded as 0x00, but OP_1 through OP_16 are encoded as 0x51 though 0x60
        if (v > 0) {
            v += 0x50;
        }
        pubkey.write(v);
        pubkey.write(data.program.length);
        pubkey.write(data.program, 0, data.program.length);
        return pubkey.toByteArray();
    }
}
