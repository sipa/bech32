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

package com.conio.wallet;

import com.conio.wallet.Bech32.Bech32Decoded;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class SegwitAddress {

    private int witnessVersion;
    private List<Integer> program;

    public SegwitAddress() { }

    private SegwitAddress(int witnessVersion, List<Integer> program) {
        this.witnessVersion = witnessVersion;
        this.program = program;
    }

    public int getWitnessVersion() {
        return witnessVersion;
    }

    public List<Integer> getProgram() {
        return program;
    }

    /**
     * Validates a Bech32 address with a given valid hrp.
     * This version of the method is useful for checking whether
     * an address is valid or not by analyzing the return value.
     * If it's null, then the provided address with the corresponding
     * hrp value cannot be validated
     *
     * @param address the Bech32 format address
     * @param hrp the hrp to to test
     * @return a payload containing the witness version and program
     */
    public SegwitAddress decode(String address, String hrp) {
        try {
            return decodeThrowing(address, hrp);
        } catch (Exception ignored) {
            return null;
        }
    }

    /**
     * Validates a Bech32 address with a given valid hrp.
     * This version of the method is useful to know the
     * reason that caused the validation to fail throwing
     * a Bech32ValidationException that can be used to
     * discriminate the various issues.
     *
     * @param address the Bech32 format address
     * @param hrp the hrp to test
     * @return a payload containing the witness version and program
     * @throws Bech32ValidationException
     */
    public SegwitAddress decodeThrowing(String address, String hrp) throws Bech32ValidationException {
        if (address.length() < 14) {
            throw new Bech32ValidationException.AddressLength("Too short");
        }

        if (address.length() > 74) {
            throw new Bech32ValidationException.AddressLength("Too long");
        }

        if ((address.length() % 8) == 0 || (address.length() % 8) == 3 || (address.length() % 8) == 5) {
            throw new Bech32ValidationException.AddressLength("Invalid length");
        }

        Bech32 bechAddress = new Bech32();
        Bech32Decoded dec = bechAddress.decode(address);

        byte[] data = Arrays.copyOfRange(dec.getData(), 1, dec.getData().length);

        List<Integer> program = convertBits(data, 5, 8, false);
        if (program == null) {
            throw new Bech32ValidationException.IncorrectFormat("Padding error");
        }

        if (program.size() < 2 || program.size() > 40) {
            throw new Bech32ValidationException.IncorrectFormat("Invalid witness program length");
        }

        if (dec.getData()[0] > 16) {
            throw new Bech32ValidationException.IncorrectFormat("Invalid witness version");
        }

        if (dec.getData()[0] == 0 && program.size() != 20 && program.size() != 32) {
            throw new Bech32ValidationException.IncorrectFormat("Invalid witness program length for v0");
        }

        if (!dec.getHrp().contains(hrp)) {
            throw new Bech32ValidationException.InvalidHumanReadablePart();
        }

        return new SegwitAddress(dec.getData()[0], program);
    }

    private List<Integer> convertBits(byte[] data, int fromBits, int toBits, boolean pad) {
        int acc = 0;
        int bits = 0;
        List<Integer> ret = new ArrayList<>();
        int maxv = (1 << toBits) - 1;

        for (int value : data) {
            if (value < 0 || (value >> fromBits) != 0) {
                return null;
            }
            acc = (acc << fromBits) | value;
            bits += fromBits;
            while (bits >= toBits) {
                bits -= toBits;
                ret.add((acc >> bits) & maxv);
            }
        }

        if (pad) {
            if (bits > 0) {
                ret.add((acc << (toBits - bits)) & maxv);
            }
        } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) != 0) {
            return null;
        }

        return ret;
    }
}

