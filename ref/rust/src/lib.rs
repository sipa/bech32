// Copyright (c) 2017 Clark Moody
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

#![warn(missing_docs)]

//! Encoding and decoding for Bech32 strings and Bitcoin Segregated Witness 
//! addresses. Bech32 is a 5-bit (base-32) encoding scheme that produces
//! strings that comprise a human-readable part, a separator, a data part,
//! and a checksum. The encoding implements a BCH code that guarantees
//! error detection of up to four characters with less than 1 in 1 billion
//! chance of failing to detect more errors.
//! 
//! The library contains `bech32` utilities for generic encoding of Bech32
//! strings and `segwit_addr` for converting witness programs to Bitcoin
//! addresses and back.
//! 
//! 

pub mod bech32;
pub mod segwit_addr;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_checksum() {
        let strings: Vec<&str> = vec!(
            "A12UEL5L",
            "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
            "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
            "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
            "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
        );
        for s in strings {
            let decode_result = bech32::decode(s.to_string());
            if !decode_result.is_ok() {
                println!("Did not decode: {:?}", s);
            }
            assert!(decode_result.is_ok());
            let encode_result = bech32::encode(decode_result.unwrap());
            assert!(encode_result.is_ok());
            assert_eq!(s.to_lowercase(), encode_result.unwrap().to_lowercase());
        }
    }

    #[test]
    fn valid_address() {
        let pairs: Vec<(&str, Vec<u8>)> = vec![
            (
                "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
                vec![
                    0x00, 0x14, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
                    0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6
                ]
            ),
            (
                "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
                vec![
                    0x00, 0x20, 0x18, 0x63, 0x14, 0x3c, 0x14, 0xc5, 0x16, 0x68, 0x04,
                    0xbd, 0x19, 0x20, 0x33, 0x56, 0xda, 0x13, 0x6c, 0x98, 0x56, 0x78,
                    0xcd, 0x4d, 0x27, 0xa1, 0xb8, 0xc6, 0x32, 0x96, 0x04, 0x90, 0x32,
                    0x62
                ]
            ),
            (
                "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx",
                vec![
                    0x81, 0x28, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
                    0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
                    0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c,
                    0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6
                ]
            ),
            (
                "BC1SW50QA3JX3S",
                vec![
                   0x90, 0x02, 0x75, 0x1e
                ]
            ),
            (
                "bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj",
                vec![
                    0x82, 0x10, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
                    0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23
                ]
            ),
            (
                "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
                vec![
                    0x00, 0x20, 0x00, 0x00, 0x00, 0xc4, 0xa5, 0xca, 0xd4, 0x62, 0x21,
                    0xb2, 0xa1, 0x87, 0x90, 0x5e, 0x52, 0x66, 0x36, 0x2b, 0x99, 0xd5,
                    0xe9, 0x1c, 0x6c, 0xe2, 0x4d, 0x16, 0x5d, 0xab, 0x93, 0xe8, 0x64,
                    0x33
                ]
            ),
        ];
        for p in pairs {
            let (address, scriptpubkey) = p;
            let mut hrp = "bc".to_string();
            let mut dec_result = segwit_addr::decode(hrp.clone(), 
                address.to_string());
            if !dec_result.is_ok() {
                hrp = "tb".to_string();
                dec_result = segwit_addr::decode(hrp.clone(), 
                    address.to_string());
                if !dec_result.is_ok() {
                    println!("Should be valid: {:?}", address);
                }
            }
            assert!(dec_result.is_ok());

            let prog = dec_result.unwrap();
            let pubkey = prog.clone().to_scriptpubkey();
            assert_eq!(pubkey, scriptpubkey);

            let enc_result = segwit_addr::encode(hrp, prog);
            assert!(enc_result.is_ok());

            let enc_address = enc_result.unwrap();
            assert_eq!(address.to_lowercase(), enc_address.to_lowercase());
        }
    }

    #[test]
    fn invalid_address() {
        let strings: Vec<&str> = vec!(
            "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
            "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
            "bc1rw5uspcuh",
            "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
            "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
            "tb1pw508d6qejxtdg4y5r3zarqfsj6c3",
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
        );
        for s in strings {
            let bc_dec_result = segwit_addr::decode("bc".to_string(), s.to_string());
            let tb_dec_result = segwit_addr::decode("tb".to_string(), s.to_string());
            if bc_dec_result.is_ok() {
                println!("Should be invalid: {:?}", s);
            }
            if tb_dec_result.is_ok() {
                println!("Should be invalid: {:?}", s);
            }
            assert!(bc_dec_result.is_err());
            assert!(tb_dec_result.is_err());
        }
    }
}
