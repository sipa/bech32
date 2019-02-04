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

package com.conio.wallet;public class Bech32ValidationException extends IllegalArgumentException {
    Bech32ValidationException() {
        super();
    }

    Bech32ValidationException(String message) {
        super(message);
    }

    static class InvalidCharacter extends Bech32ValidationException {
        final char character;
        final int position;

        InvalidCharacter(char character, int position) {
            super("Invalid character '" + character + "' at position " + position);
            this.character = character;
            this.position = position;
        }
    }

    static class ContainsMixedCase extends Bech32ValidationException {

        ContainsMixedCase() {
            super("Mixed case");
        }
    }

    static class InvalidHumanReadablePart extends Bech32ValidationException {

        InvalidHumanReadablePart() {
            super("Invalid human-readable part");
        }
    }

    static class InvalidSeparator extends Bech32ValidationException {

        InvalidSeparator() {
            super("Missing, or placed in a wrong position, '1' separator");
        }
    }

    static class AddressLength extends Bech32ValidationException {

        AddressLength(String message) {
            super(message);
        }
    }

    static class IncorrectFormat extends Bech32ValidationException {

        IncorrectFormat(String message) {
            super(message);
        }
    }
}
