/*
 * # Copyright (c) 2019 Lorenzo Zanotto
 * #
 * # Permission is hereby granted, free of charge, to any person obtaining a copy
 * # of this software and associated documentation files (the "Software"), to deal
 * # in the Software without restriction, including without limitation the rights
 * # to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * # copies of the Software, and to permit persons to whom the Software is
 * # furnished to do so, subject to the following conditions:
 * #
 * # The above copyright notice and this permission notice shall be included in
 * # all copies or substantial portions of the Software.
 * #
 * # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * # IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * # FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * # AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * # LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * # OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * # THE SOFTWARE.
 */

import com.conio.wallet.Bech32;
import com.conio.wallet.Bech32ValidationException;
import com.conio.wallet.SegwitAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.Assert;
import org.junit.Test;

public class Bech32ValidationTest {

    // Classes Under Tests

    private SegwitAddress mSegwitAddress = new SegwitAddress();
    private Bech32 mBech32 = new Bech32();

    // Checksums

    @Test
    public void testValidChecksums() throws Bech32ValidationException {
        String[] validChecksums = TestVectors.validChecksums;
        int validChecksumCount = 0;
        for (String checksum: validChecksums) {
            mBech32.decode(checksum);
            validChecksumCount++;
        }

        boolean testPassed = validChecksumCount == validChecksums.length;
        communicateResult("[Valid Checksum]", testPassed);
        Assert.assertTrue(testPassed);
    }

    @Test
    public void testInvalidChecksum() {
        String[] invalidChecksums = TestVectors.invalidChecksums;
        int validChecksumCount = 0;
        for (String checksum: invalidChecksums) {
            try {
                mBech32.decode(checksum);
                validChecksumCount++;
            } catch (Exception ignored) { }
        }

        boolean testPassed = validChecksumCount == 0;
        communicateResult("[Invalid Checksum]", testPassed);
        Assert.assertTrue(testPassed);
    }

    // Addresses

    @Test
    public void testValidAddress() {
        int index = 0;
        for (String address: TestVectors.validAddress) {
            String hrp = "bc";
            SegwitAddress decoded = mSegwitAddress.decode(address, hrp);
            if (decoded == null) {
                hrp = "tb";
                decoded = mSegwitAddress.decode(address, hrp);
            }

            if (decoded != null) {
                System.out.println("[Valid address] decoded witver: " + decoded.getWitnessVersion());
            }

            int[] expectedScriptPubKey = TestVectors.validAddressPubKeys[index];
            int[] scriptPubKey = scriptPubKey(decoded.getWitnessVersion(), decoded.getProgram());

            boolean arePubKeysEqual = Arrays.equals(expectedScriptPubKey, scriptPubKey);
            index++;
            communicateResult("[Valid address " + address + " pub key match]", arePubKeysEqual);
            Assert.assertTrue(arePubKeysEqual);
        }
    }

    @Test
    public void testInvalidAddress() {
        for (String address: TestVectors.invalidAddress) {
            SegwitAddress main = mSegwitAddress.decode(address, "bc");
            if (main == null) communicateResult("[Invalid address " + address + " not decoded]", true);
            SegwitAddress test = mSegwitAddress.decode(address, "tb");
            if (test == null) communicateResult("[Invalid address " + address + " not decoded]", true);
            Assert.assertNull(main);
            Assert.assertNull(test);
        }
    }

    // Script Pub Key

    private int[] scriptPubKey(int version, List<Integer> program) {
        List<Integer> res = new ArrayList<>();
        res.add(version != 0 ? version + 0x50 : 0);
        res.add(program.size());
        res.addAll(program);

        return listToByteArray(res);
    }

    private int[] listToByteArray(List<Integer> list) {
        int length = list.size();
        int[] output = new int[length];

        for (int i = 0; i < length; i++) {
            output[i] = list.get(i);
        }

        return output;
    }

    private void communicateResult(String testName, boolean result) {
        String returnValue = result ? "OK" : "FAILED";
        System.out.println(testName + " [" + returnValue + "]");
    }
}
