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

//! Encode and decode the Bech32 format, with checksums
//! 
//! 
//! 

use std::fmt;
use std::error::Error;

#[derive(Debug)]
pub struct Bech32 {
    pub hrp: String,
    pub data: Vec<u8>
}

impl Bech32 {
    pub fn clone(&self) -> Bech32 {
        Bech32 {
            hrp: self.hrp.clone(),
            data: self.data.to_vec()
        }
    }
}

// Human-readable part and data part separator
const SEP: char = '1';

// Encoding character set. Maps data value -> char
const CHARSET: [char; 32] = [
    'q','p','z','r','y','9','x','8',
    'g','f','2','t','v','d','w','0',
    's','3','j','n','5','4','k','h',
    'c','e','6','m','u','a','7','l'
];

// Reverse character set. Maps ASCII byte -> CHARSET index on [0,31]
const CHARSET_REV: [i8; 128] = [
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
];

// Generator coefficients
const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

pub fn encode(b: Bech32) -> EncodeResult {
    let hrp_bytes: Vec<u8> = b.hrp.clone().into_bytes();
    let mut combined: Vec<u8> = b.data.clone();
    combined.extend_from_slice(&create_checksum(&hrp_bytes, &b.data));
    let mut ret: String = format!("{}{}", b.hrp, SEP);
    for p in combined {
        ret.push(CHARSET[p as usize]);
    }
    Ok(ret)
}

pub fn decode(s: String) -> DecodeResult {
    // Ensure overall length is within bounds
    let len: usize = s.len();
    if len < 8 || len > 90 {
        return Err(CodingError::InvalidLength)
    }

    // Split at separator and check for two pieces
    let parts: Vec<&str> = s.rsplitn(2, SEP).collect();
    if parts.len() != 2 {
        return Err(CodingError::InvalidChar)
    }
    let raw_hrp = parts[1];
    let raw_data = parts[0];
    if raw_hrp.len() < 1 || raw_data.len() < 6 {
        return Err(CodingError::InvalidLength)
    }

    let mut has_lower: bool = false;
    let mut has_upper: bool = false;
    let mut hrp_bytes: Vec<u8> = Vec::new();
    for b in raw_hrp.bytes() {
        // Valid subset of ASCII
        if b < 33 || b > 126 {
            return Err(CodingError::InvalidChar)
        }
        let mut c = b;
        // Lowercase
        if b >= 97 && b <= 122 {
            has_lower = true;
        }
        // Uppercase
        if b >= 65 && b <= 90 {
            has_upper = true;
            // Convert to lowercase
            c = b + (97-65);
        }
        hrp_bytes.push(c);
    }

    // Ensure no mixed case
    if has_lower && has_upper {
        return Err(CodingError::MixedCase)
    }

    // Check data payload
    let mut data_bytes: Vec<u8> = Vec::new();
    for b in raw_data.bytes() {
        // Aphanumeric only
        if !((b >= 48 && b <= 57) || (b >= 65 && b <= 90) || (b >= 97 && b <= 122)) {
            return Err(CodingError::InvalidChar)
        }
        // Excludes these characters: [1,b,i,o]
        if b == 49 || b == 98 || b == 105 || b == 111 {
            return Err(CodingError::InvalidChar)
        }
        // Lowercase
        if b >= 97 && b <= 122 {
            has_lower = true;
        }
        let mut c = b;
        // Uppercase
        if b >= 65 && b <= 90 {
            has_upper = true;
            // Convert to lowercase
            c = b + (97-65);
        }
        data_bytes.push(CHARSET_REV[c as usize] as u8);
    }

    // Ensure no mixed case
    if has_lower && has_upper {
        return Err(CodingError::MixedCase)
    }

    // Ensure checksum
    if !verify_checksum(&hrp_bytes, &data_bytes) {
        return Err(CodingError::InvalidChecksum)
    }

    // Remove checksum from data payload
    let dbl: usize = data_bytes.len();
    data_bytes.truncate(dbl - 6);

    Ok(Bech32 {
        hrp: String::from_utf8(hrp_bytes).unwrap(),
        data: data_bytes
    })
}

fn create_checksum(hrp: &Vec<u8>, data: &Vec<u8>) -> Vec<u8> {
    let mut values: Vec<u8> = hrp_expand(hrp);
    values.extend_from_slice(data);
    let pad: Vec<u8> = vec![0,0,0,0,0,0];
    values.extend_from_slice(&pad);
    let plm: u32 = polymod(values) ^ 1;
    let mut checksum: Vec<u8> = Vec::new();
    for p in 0..6 {
        checksum.push(((plm >> 5 * (5 - p)) & 0x1f) as u8);
    }
    checksum
}

fn verify_checksum(hrp: &Vec<u8>, data: &Vec<u8>) -> bool {
    let mut exp = hrp_expand(hrp);
    exp.extend_from_slice(data);
    polymod(exp) == 1u32
}

fn hrp_expand(hrp: &Vec<u8>) -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    for b in hrp {
        v.push(*b >> 5);
    }
    v.push(0);
    for b in hrp {
        v.push(*b & 0x1f);
    }
    v
}

fn polymod(values: Vec<u8>) -> u32 {
    let mut chk: u32 = 1;
    let mut b: u8;
    for v in values {
        b = (chk >> 25) as u8;
        chk = (chk & 0x1ffffff) << 5 ^ (v as u32);
        for i in 0..5 {
            if (b >> i) & 1 == 1 {
                chk ^= GEN[i]
            }
        }
    }
    chk
}

#[derive(Debug)]
pub enum CodingError {
    InvalidChecksum,
    InvalidLength,
    InvalidChar,
    MixedCase,
}

impl fmt::Display for CodingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CodingError::InvalidChecksum => write!(f, "Invalid checksum."),
            CodingError::InvalidLength => write!(f, "Invalid length."),
            CodingError::InvalidChar => write!(f, "Invalid character."),
            CodingError::MixedCase => write!(f, "Mixed-case strings not allowed."),
        }
    }
}

impl Error for CodingError {
    fn description(&self) -> &str {
        match *self {
            CodingError::InvalidChecksum => "Invalid checksum.",
            CodingError::InvalidLength => "Invalid length.",
            CodingError::InvalidChar => "Invalid character.",
            CodingError::MixedCase => "Mixed-case strings not allowed.",
        }
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            CodingError::InvalidChecksum => None,
            CodingError::InvalidLength => None,
            CodingError::InvalidChar => None,
            CodingError::MixedCase => None,
        }
    }
}

pub type DecodeResult = Result<Bech32, CodingError>;
pub type EncodeResult = Result<String, CodingError>;
