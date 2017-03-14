var bech32_ecc = require('./bech32_ecc');

module.exports = {
  check: check
};

function convertbits (data, frombits, tobits, pad) {
  var acc = 0;
  var bits = 0;
  var ret = [];
  var maxv = (1 << tobits) - 1;
  for (var p = 0; p < data.length; ++p) {
    var value = data[p];
    if (value < 0 || (value >> frombits) !== 0) {
      return null;
    }
    acc = (acc << frombits) | value;
    bits += frombits;
    while (bits >= tobits) {
      bits -= tobits;
      ret.push((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) {
      ret.push((acc << (tobits - bits)) & maxv);
    }
  } else if (bits >= frombits || ((acc << (tobits - bits)) & maxv)) {
    return null;
  }
  return ret;
}

function check (addr) {
  var dec = bech32_ecc.check(addr);
  if (dec.error !== null) {
    return {error:dec.error, pos:dec.pos};
  }
  if (dec.data.length < 1) {
    return {error:"Too short", pos:null};
  }
  var res = convertbits(dec.data.slice(1), 5, 8, false);
  if (res === null) {
    return {error:"Padding error", pos:[addr.length - 6]};
  }
  if (res.length < 2 || res.length > 40) {
    return {error:"Invalid witness program length", pos:null};
  }
  if (dec.data[0] > 16) {
    return {error:"Invalid witness version", pos:[dec.hrp.length + 1]};
  }
  if (dec.data[0] === 0 && res.length !== 20 && res.length !== 32) {
    return {error:"Invalid witness program length for v0", pos:null};
  }
  return null;
}
