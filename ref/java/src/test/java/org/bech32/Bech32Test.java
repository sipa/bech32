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

import org.junit.Test;

import java.util.Locale;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class Bech32Test {
    @Test
    public void validChecksum() throws Bech32.Bech32Exception {
        for (String valid : VALID_CHECKSUM) {
            Bech32.Bech32Data dec = Bech32.decode(valid);
            String recode = Bech32.encode(dec);
            assertEquals(String.format("Failed to roundtrip '%s' -> '%s'", valid, recode),
                    valid.toLowerCase(Locale.ROOT), recode.toLowerCase(Locale.ROOT));
            // Test encoding with an uppercase HRP
            recode = Bech32.encode(dec.hrp.toUpperCase(Locale.ROOT), dec.values);
            assertEquals(String.format("Failed to roundtrip '%s' -> '%s'", valid, recode),
                    valid.toLowerCase(Locale.ROOT), recode.toLowerCase(Locale.ROOT));
        }
    }

    @Test
    public void invalidChecksum() {
        for (String invalid : INVALID_CHECKSUM) {
            try {
                Bech32.decode(invalid);
                fail(String.format("Parsed an invalid code: '%s'", invalid));
            } catch (Bech32.Bech32Exception e) {
                /* expected */
            }
        }
    }

    @Test
    public void validAddress() throws Bech32.Bech32Exception, SegwitAddress.SegwitAddressException {
        for (AddressData valid : VALID_ADDRESS) {
            assertValidAddress(valid, false);
            assertValidAddress(valid, true);
        }
    }

    private void assertValidAddress(AddressData valid, boolean hrpUppercase)
            throws SegwitAddress.SegwitAddressException {
        String hrp = hrpUppercase ? "BC" : "bc";
        SegwitAddress.SegwitAddressData dec;
        try {
            dec = SegwitAddress.decode(hrp, valid.address);
        } catch (SegwitAddress.SegwitAddressException e) {
            hrp = hrpUppercase ? "TB" : "tb";
            dec = SegwitAddress.decode(hrp, valid.address);
        }

        byte[] spk = SegwitAddress.toScriptpubkey(dec);
        assertArrayEquals(String.format("decode produces wrong result: '%s'", valid.address),
                valid.scriptPubKey, spk);

        String recode = SegwitAddress.encode(hrp, dec.version, dec.program);
        assertEquals(String.format("encode roundtrip fails: '%s' -> '%s'",
                valid.address.toLowerCase(Locale.ROOT), recode),
                valid.address.toLowerCase(Locale.ROOT), recode);
    }

    @Test
    public void invalidAddress() {
        for (String invalid : INVALID_ADDRESS) {
            try {
                SegwitAddress.decode("bc", invalid);
                fail(String.format("Parsed an invalid address: '%s'", invalid));
            } catch (SegwitAddress.SegwitAddressException e) { /* expected */ }
            try {
                SegwitAddress.decode("tb", invalid);
                fail(String.format("Parsed an invalid address: '%s'", invalid));
            } catch (SegwitAddress.SegwitAddressException e) { /* expected */ }
        }
    }

    @Test
    public void invalidAddressEncoding() {
        for (InvalidAddressData invalid : INVALID_ADDRESS_ENC) {
            try {
                String code = SegwitAddress.encode(invalid.hrp, invalid.version, new byte[invalid.program_length]);
                fail(String.format("Encode succeeds on invalid '%s'", code));
            } catch (SegwitAddress.SegwitAddressException e) { /* expected */ }
        }
    }

    @Test
    public void invalidHrp() throws Bech32.Bech32Exception {
        byte[] program = new byte[20];
        for (String invalidHrp : INVALID_HRP_ENC) {
            try {
                String code = SegwitAddress.encode(invalidHrp, 0, program);
                fail(String.format("Encode succeeds on invalid '%s'", code));
            } catch (SegwitAddress.SegwitAddressException e) { /* expected */ }
        }
    }

    // test vectors
    private static String[] VALID_CHECKSUM = {
            "A12UEL5L",
            "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
            "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
            "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
            "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w"
    };

    private static String[] INVALID_CHECKSUM = {
            " 1nwldj5",
            new String(new char[] { 0x7f }) + "1axkwrx",
            "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
            "pzry9x0s0muk",
            "1pzry9x0s0muk",
            "x1b4n0q5v",
            "li1dgmt3",
            "de1lg7wt" + new String(new char[] { 0xff }),
    };

    private static class AddressData {
        final String address;
        final byte scriptPubKey[];

        AddressData(String address, String scriptPubKeyHex) {
            this.address = address;
            // Convert hex to bytes, does minimal error checking
            int len = scriptPubKeyHex.length();
            scriptPubKey = new byte[len / 2];
            for (int i = 0; i < len; i += 2) {
                scriptPubKey[i / 2] = (byte) ((Character.digit(scriptPubKeyHex.charAt(i), 16) << 4)
                        + Character.digit(scriptPubKeyHex.charAt(i+1), 16));
            }
        }
    }

    private static AddressData[] VALID_ADDRESS = {
            new AddressData("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", "0014751e76e8199196d454941c45d1b3a323f1433bd6"),
            new AddressData("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7","00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"),
            new AddressData("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx", "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"),
            new AddressData("BC1SW50QA3JX3S", "6002751e"),
            new AddressData("bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj", "5210751e76e8199196d454941c45d1b3a323"),
            new AddressData("tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy", "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"),
    };

    private static String[] INVALID_ADDRESS = {
            "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
            "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
            "bc1rw5uspcuh",
            "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
            "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
            "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
            "bc1gmk9yu",
    };

    private static class InvalidAddressData {
        final String hrp;
        final int version;
        final int program_length;

        InvalidAddressData(String hrp, int version, int program_length) {
            this.hrp = hrp;
            this.version = version;
            this.program_length = program_length;
        }
    }

    private static InvalidAddressData[] INVALID_ADDRESS_ENC = {
            new InvalidAddressData("bc", 0, 21),
            new InvalidAddressData("bc", 17, 32),
            new InvalidAddressData("bc", 1, 1),
            new InvalidAddressData("bc", 16, 41),
    };

    private static String[] INVALID_HRP_ENC = {
            "café",
            "μπίτκοιν",
            "бит",
            "コイン",
    };
}
