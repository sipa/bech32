bech32 = function() {
    var BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    var BECH32_GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

    function polymod(values) {
        var chk = 1;
        for (var p = 0; p < values.length; ++p) {
            var top = chk >> 25;
            chk = (chk & 0x1ffffff) << 5 ^ values[p];
            for (var i = 0; i < 5; ++i) {
                if ((top >> i) & 1) {
                    chk ^= BECH32_GENERATOR[i];
                }
            }
        }
        return chk;
    }


    function hrp_expand(hrp) {
        var ret = [];
        for (var p = 0; p < hrp.length; ++p) {
            ret.push(hrp.charCodeAt(p) >> 5);
        }
        ret.push(0);
        for (var p = 0; p < hrp.length; ++p) {
            ret.push(hrp.charCodeAt(p) & 31);
        }
        return ret;
    }

    function verify_checksum(hrp, data) {
        return polymod(hrp_expand(hrp).concat(data)) == 1
    }

    function create_checksum(hrp, data) {
        var values = hrp_expand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);
        var mod = polymod(values) ^ 1;
        var ret = [];
        for (var p = 0; p < 6; ++p) {
            ret.push((mod >> 5 * (5 - p)) & 31);
        }
        return ret;
    }

    function encode(hrp, data) {
        var combined = data.concat(create_checksum(hrp, data));
        var ret = hrp + "1";
        for (var p = 0; p < combined.length; ++p) {
            ret += BECH32_CHARSET.charAt(combined[p]);
        }
        return ret;
    }

    function decode(bech_string) {
        for (var p = 0; p < bech_string.length; ++p) {
            if (bech_string.charCodeAt(p) < 32 || bech_string.charCodeAt(p) > 126) {
                return null;
            }
        }
        var pos = bech_string.lastIndexOf("1");
        if (pos < 1 || pos + 7 > bech_string.length || bech_string.length > 90) {
            return null;
        }
        var hrp = bech_string.substring(0, pos);
        var data = [];
        for (var p = pos + 1; p < bech_string.length; ++p) {
            var d = BECH32_CHARSET.indexOf(bech_string.charAt(p));
            if (d == -1) {
                return null;
            }
            data.push(d);
        }
        if (!verify_checksum(hrp, data)) {
            return null;
        }
        return {hrp: hrp, data: data.slice(0, data.length - 6)};
    }

    return {
        encode: encode,
        decode: decode
    };
}();

segwit_addr = function() {
    function convertbits(data, frombits, tobits, pad) {
        var acc = 0;
        var bits = 0;
        var ret = [];
        var maxv = (1 << tobits) - 1;
        for (var p = 0; p < data.length; ++p) {
            var value = data[p];
            if (value < 0 || (value >> frombits) != 0) {
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

    function decode(hrp, addr) {
        var has_lower = false;
        var has_upper = false;
        for (var p = 0; p < addr.length; ++p) {
            var c = addr.charAt(p);
            if (c >= 'a' && c <= 'z') {
                has_lower = true;
            } else if (c >= 'A' && c <= 'Z') {
                has_upper = true;
            } else if (!(c >= '0' && c <= '9')) {
                return null;
            }
        }
        if (has_lower && has_upper) {
            return null;
        }
        dec = bech32.decode(addr.toLowerCase());
        if (dec === null || dec.hrp != hrp || dec.data.length < 1 || dec.data[0] > 16) {
            return null;
        }
        res = convertbits(dec.data.slice(1), 5, 8, false);
        if (res === null || res.length < 2 || res.length > 40) {
            return null;
        }
        if (dec.data[0] == 0 && res.length != 20 && res.length != 32) {
            return null;
        }
        return {version: dec.data[0], program: res};
    }

    function encode(hrp, version, program) {
        var ret = bech32.encode(hrp, [version].concat(convertbits(program, 8, 5, true)));
        if (decode(hrp, ret) === null) {
            return null;
        }
        return ret;
    }

    return {
        decode: decode,
        encode: encode
    };
}();

if (typeof exports !== 'undefined') {
    exports.bech32_encode = bech32.encode;
    exports.bech32_decode = bech32.decode;
    exports.encode = segwit_addr.encode;
    exports.decode = segwit_addr.decode;
}
