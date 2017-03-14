var CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
var GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

module.exports = {
  decode: decode,
  encode: encode,
};


function polymod (values) {
  var chk = 1;
  for (var p = 0; p < values.length; ++p) {
    var top = chk >> 25;
    chk = (chk & 0x1ffffff) << 5 ^ values[p];
    for (var i = 0; i < 5; ++i) {
      if ((top >> i) & 1) {
        chk ^= GENERATOR[i];
      }
    }
  }
  return chk;
}

function hrpExpand (hrp) {
  var ret = [];
  var p;
  for (p = 0; p < hrp.length; ++p) {
    ret.push(hrp.charCodeAt(p) >> 5);
  }
  ret.push(0);
  for (p = 0; p < hrp.length; ++p) {
    ret.push(hrp.charCodeAt(p) & 31);
  }
  return ret;
}

function verifyChecksum (hrp, data) {
  return polymod(hrpExpand(hrp).concat(data)) === 1;
}

function createChecksum (hrp, data) {
  var values = hrpExpand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);
  var mod = polymod(values) ^ 1;
  var ret = [];
  for (var p = 0; p < 6; ++p) {
    ret.push((mod >> 5 * (5 - p)) & 31);
  }
  return ret;
}

function encode (hrp, data) {
  var combined = data.concat(createChecksum(hrp, data));
  var ret = hrp + '1';
  for (var p = 0; p < combined.length; ++p) {
    ret += CHARSET.charAt(combined[p]);
  }
  return ret;
}

function decode (bechString) {
  var p;
  var has_lower = false;
  var has_upper = false;
  for (p = 0; p < bechString.length; ++p) {
    if (bechString.charCodeAt(p) < 32 || bechString.charCodeAt(p) > 126) {
      return null;
    }
    if (bechString.charAt(p) >= 'a' && bechString.charAt(p) <= 'z') {
        has_lower = true;
    }
    if (bechString.charAt(p) >= 'A' && bechString.charAt(p) <= 'Z') {
        has_upper = true;
    }
  }
  if (has_lower && has_upper) return null;
  bechString = bechString.toLowerCase();
  var pos = bechString.lastIndexOf('1');
  if (pos < 1 || pos + 7 > bechString.length || bechString.length > 90) {
    return null;
  }
  var hrp = bechString.substring(0, pos);
  var data = [];
  for (p = pos + 1; p < bechString.length; ++p) {
    var d = CHARSET.indexOf(bechString.charAt(p));
    if (d === -1) {
      return null;
    }
    data.push(d);
  }
  if (!verifyChecksum(hrp, data)) {
    return null;
  }
  return {hrp: hrp, data: data.slice(0, data.length - 6)};
}
