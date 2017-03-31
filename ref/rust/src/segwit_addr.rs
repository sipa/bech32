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

use bech32;

/// Witness `WitnessProgram` type
#[derive(Debug)]
pub struct WitnessProgram {
    /// Witness program version
    pub version: u8,
    /// Witness program content
    pub program: Vec<u8>
}

impl WitnessProgram {
    /// Converts a `WitnessProgram` to a script public key
    ///
    /// The format for the output is 
    /// `[version, program length, <program>]`
    pub fn to_scriptpubkey(&self) -> Vec<u8> {
        let mut pubkey: Vec<u8> = Vec::new();
        let mut v = self.version;
        if v > 0 {
            v += 0x80;
        }
        pubkey.push(v);
        pubkey.push(self.program.len() as u8);
        pubkey.extend_from_slice(&self.program);
        pubkey
    }

    pub fn from_scriptpubkey(pubkey: Vec<u8>) -> Result<WitnessProgram, ()> {
        // TODO: Validate according to BIP141
        
        // We need a version byte and a program length byte, with a program at 
        // least 2 bytes long.
        if pubkey.len() < 4 {
            return Err(())
        }
        let proglen: usize = pubkey[1] as usize;
        // Check that program length byte is consistent with pubkey length
        if pubkey.len() != 2 + proglen {
            return Err(())
        }
        // Process script version
        let mut v: u8 = pubkey[0];
        if v > 0x80 {
            v -= 0x80;
        }
        let (_, program) = pubkey.split_at(2);
        Ok(WitnessProgram {
            version: v,
            program: program.to_vec()
        })
    }

    pub fn clone(&self) -> WitnessProgram {
        WitnessProgram {
            version: self.version,
            program: self.program.to_vec()
        }
    }
}

pub fn encode(hrp: String, p: WitnessProgram) -> EncodeResult {
    let mut data: Vec<u8> = vec![p.version];
    // Convert 8-bit program into 5-bit
    let p5 = match convert_bits(p.program.to_vec(), 8, 5, true) {
        Ok(p) => p,
        Err(_) => {
            return Err(bech32::CodingError::InvalidChar)
        }
    };
    data.extend_from_slice(&p5);
    let enc_result = bech32::encode(
        bech32::Bech32 {hrp: hrp.clone(), data: data});
    if enc_result.is_err() {
        return Err(bech32::CodingError::InvalidChar)
    }
    let address = enc_result.unwrap();
    let dec_result = decode(hrp, address.clone());
    if dec_result.is_err() {
        return Err(bech32::CodingError::InvalidChar)
    }
    Ok(address)
}

/// Decodes a segwit address
///
/// Verifies that the `address` contains the expected human-readable part `hrp`
/// and decodes as proper Bech32-encoded string.
/// 
/// Returns the witness `WitnessProgram`
/// 
/// 
/// # Examples
/// 
pub fn decode(hrp: String, address: String) -> DecodeResult {
    let dec = bech32::decode(address);
    if dec.is_err() {
        return Err(dec.unwrap_err())
    }
    let b32 = dec.unwrap();
    if b32.hrp != hrp {
        return Err(bech32::CodingError::InvalidChar)
    }
    if b32.data.len() == 0 || b32.data.len() > 65 {
        return Err(bech32::CodingError::InvalidLength)
    }
    if b32.data[0] > 16 {
        // Invalid script version
        return Err(bech32::CodingError::InvalidChar)
    }
    let mut ret = WitnessProgram {
        version: b32.data[0],
        program: Vec::new()
    };
    // Get the 5-bit program
    let (_, p5) = b32.data.split_at(1);
    // Convert to 8-bit program
    let p8 = match convert_bits(p5.to_vec(), 5, 8, false) {
        Ok(p) => p,
        Err(_) => {
            return Err(bech32::CodingError::InvalidChar)
        },
    };
    if p8.len() < 2 || p8.len() > 40 {
        return Err(bech32::CodingError::InvalidLength)    
    }
    // Check proper script length
    if ret.version == 0 && p8.len() != 20 && p8.len() != 32 {
        return Err(bech32::CodingError::InvalidLength)    
    }
    ret.program = p8;
    Ok(ret)
}

/// Convert between bit sizes
///
/// # Panics
/// Function will panic if attempting to convert `from` or `to` a bit size that
/// is larger than 8 bits.
fn convert_bits(data: Vec<u8>, from: u32, to: u32, pad: bool) -> ConvertResult {
    if from > 8 || to > 8 {
        panic!("convert_bits `from` and `to` parameters greater than 8");
    }
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut ret: Vec<u8> = Vec::new();
    let maxv: u32 = (1<<to) - 1;
    for value in data {
        let v: u32 = value as u32;
        if (v >> from) != 0 {
            // Input value exceeds `from` bit size
            return Err(())
        }
        acc = (acc << from) | v;
        bits += from;
        while bits >= to {
            bits -= to;
            ret.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            ret.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return Err(())
    }
    Ok(ret)
}

type ConvertResult = Result<Vec<u8>, ()>;

type DecodeResult = Result<WitnessProgram, bech32::CodingError>;
type EncodeResult = bech32::EncodeResult;
