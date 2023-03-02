// Copyright (c) 2020 J.K. Zhou
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


// This file is just a re-write of bech32 python version
// Thanks to Pieter Wuille

var CHARSET = [
  'q','p','z','r','y','9','x','8',
  'g','f','2','t','v','d','w','0',
  's','3','j','n','5','4','k','h',
  'c','e','6','m','u','a','7','l'];

var GENERATOR = [
  0x3b6a57b2,
  0x26508e6d,
  0x1ea119fa,
  0x3d4233dd,
  0x2a1462b3
];

int bech32_polymod(List<int> values) {
  int chk = 1;
  values.forEach((v) {
    var top = chk >> 25;
    chk = (chk & 0x1ffffff) << 5 ^ v;
    for(var i = 0; i < 5; i ++) {
      chk ^= (top >> i) & 0x01 > 0 ? GENERATOR[i] : 0;
    }
  });
  return chk;
}

List<int> bech32_hrp_expand(String hrp) {
  var codes = hrp.codeUnits;
  List<int> ret = [];
  ret.addAll(codes.map((i) => i >> 5));
  ret.add(0);
  ret.addAll(codes.map((i) => i & 31));
  return ret;
}

/// Compute checksum values given HRP and data
List<int> bech32_create_checksum(String hrp, List<int> data) {
  var values = bech32_hrp_expand(hrp) + data;
  var polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1;
  return [0, 1, 2, 3, 4, 5].map((i) => (polymod >> 5 * (5 - i)) & 0x1f).toList();
}

bool bech32_verify_checksum(String hrp, List<int> data) {
  return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1;
}

String bech32_encode(String hrp, List<int> data) {
  var combined = data + bech32_create_checksum(hrp, data);
  return hrp + '1' + combined.map((i) => CHARSET[i]).join('');
}

/// Validate a bech32 string, and return a list containing HRP and validated data
/// 
/// If validate fails, throw Exception
List<dynamic> bech32_decode(String bech) {
  if(bech.length > 90) {
    throw Exception('invalid address format, length too long');
  }
  if(bech.toLowerCase() != bech && bech.toUpperCase() != bech) {
    throw Exception('mixin use of lower and upper chars');
  }
  bech = bech.toLowerCase();
  var pos = bech.indexOf('1');
  if(pos < 1 || pos + 7 > bech.length) {
    throw Exception('invalid split char position');
  }

  for(var i = 0; i < pos; i++) {
    var c = bech.codeUnitAt(i);
    if(c < 33 || c > 126)
      throw Exception('invalid hrp character at index ${i}');
  }
  List<int> data = [];
  for(var i = pos + 1; i < bech.length; i++) {
    var c = String.fromCharCode(bech.codeUnitAt(i));
    var idx = CHARSET.indexOf(c);
    if(idx == -1) {
      throw Exception('invalid data character at index ${i}');
    }
    data.add(idx);
  }
  var hrp = bech.substring(0, pos);
  if(!bech32_verify_checksum(hrp, data)) {
    throw Exception('invalid bech32 checksum');
  }

  return [hrp, data.sublist(0, data.length - 6)];
}

/// General Power-of-2 base conversion
List<int> convertBits(List<int> data, int fromBits, int toBits, {bool pad = true}) {
  List<int> ret = [];
  var acc = 0;
  var bits = 0;
  var maxV = (1 << toBits) - 1;
  var maxAcc = (1 << (fromBits + toBits - 1)) - 1;
  data.forEach((v) {
    if(v < 0 || (v >> fromBits) > 0) {
      return null;
    }
    acc = ((acc << fromBits) | v) & maxAcc;
    bits += fromBits;
    while(bits >= toBits) {
      bits -= toBits;
      ret.add((acc >> bits) & maxV);
    }
  });

  if(pad) {
    if(bits > 0) {
      ret.add((acc << (toBits - bits)) & maxV);
    }
  } else {
    if(bits >= fromBits || ((acc << (toBits - bits)) & maxV > 0)) {
      return null;
    }
  }
  return ret;
}

/// decode a bech32 address with given hrp
/// 
/// return a list containing two items:
/// [witVer, witProg]
/// 
/// where witVer is an integer and witProg is List<int>
/// 
/// throws exception if bech32 validation fails
List<dynamic> decode(String hrp, String addr) {
  var ret = bech32_decode(addr);
  var hrpFromAddr = ret[0] as String;
  var data = ret[1] as List<int>;
  if(hrpFromAddr != hrp) {
    throw Exception("incompatible hrp");
  }

  if(data.length == 0) {
    throw Exception("invalid address");
  }
  var decoded = convertBits(data.sublist(1), 5, 8, pad: false);
  if(decoded == null || decoded.length < 2 || decoded.length > 40) {
    throw Exception("invalid address");
  }
  if(data[0] > 16) {
    throw Exception("invalid address");
  }

  if(data[0] == 0 && decoded.length != 20 && decoded.length != 32) {
    throw Exception("invalid address length");
  }
  return [data[0], decoded];
}

String encode(String hrp, int witVer, List<int> witProg) {
  var ret = bech32_encode(hrp, [witVer] + convertBits(witProg, 8, 5));
  return ret;
}