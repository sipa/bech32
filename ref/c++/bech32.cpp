/* Copyright (c) 2017 Pieter Wuille
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdint.h>
#include "bech32.h"

namespace bech32 {
namespace {

const char* charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

const char separator = '1';

const int8_t charset_rev[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
};

inline int32_t polymod_step(int32_t chk) {
    uint8_t b = chk >> 25;
    return ((chk & 0x1FFFFFF) << 5) ^
        (-((b >> 0) & 1) & 0x3b6a57b2UL) ^
        (-((b >> 1) & 1) & 0x26508e6dUL) ^
        (-((b >> 2) & 1) & 0x1ea119faUL) ^
        (-((b >> 3) & 1) & 0x3d4233ddUL) ^
        (-((b >> 4) & 1) & 0x2a1462b3UL);
}

inline unsigned char to_lc(unsigned char c) {
    return c >= 'A' && c <= 'Z' ? (c - 'A') + 'a' : c;
}

template<typename H>
int32_t checksum_hrp(H hrp_begin, H hrp_end) {
    int32_t chk = 1;
    H hrp_iter = hrp_begin;
    while (hrp_iter != hrp_end) {
        uint8_t c = *(hrp_iter++);
        if (c <= 32 || c >= 127) return -1;
        chk = polymod_step(chk) ^ (to_lc(c) >> 5);
    }
    chk = polymod_step(chk);
    while (hrp_begin != hrp_end) {
        uint8_t c = *(hrp_begin++);
        chk = polymod_step(chk) ^ (to_lc(c) & 0x1f);
    }
    return chk;
}

template<typename D, typename H>
int32_t checksum_data(D data_begin, D data_end, H hrp_begin, H hrp_end) {
    int32_t chk = checksum_hrp(hrp_begin, hrp_end);
    if (chk == -1) return -1;
    while (data_begin != data_end) {
        uint8_t c = *(data_begin++);
        if (c > 32) return -1;
        chk = polymod_step(chk) ^ c;
    }
    for (int i = 0; i < 6; ++i) {
        chk = polymod_step(chk);
    }
    return chk ^ 1;
}

template<typename S, typename H>
int32_t checksum_str(S str_begin, S str_end, H hrp_begin, H hrp_end) {
    int32_t chk = checksum_hrp(hrp_begin, hrp_end);
    if (chk == -1) return -1;
    while (str_begin != str_end) {
        unsigned char c = *(str_begin++);
        if (c > 128 || charset_rev[c] == -1) return -1;
        chk = polymod_step(chk) ^ charset_rev[c];
    }
    return chk ^ 1;
}

}

std::string encode(const std::string& hrp, const data& d) {
    if (hrp.size() < 1 || d.size() + 1 + hrp.size() > 90) return "";
    int32_t chk = checksum_data(d.begin(), d.end(), hrp.begin(), hrp.end());
    if (chk == -1) return "";
    std::string ret = hrp;
    ret.reserve(hrp.size() + 1 + d.size() + 6);
    ret += separator;
    for (size_t i = 0; i < d.size(); ++i) {
        ret += charset[d[i]];
    }
    for (int i = 0; i < 6; ++i) {
        ret += charset[(chk >> (5 * (5 - i))) & 0x1f];
    }
    return ret;
}

std::pair<std::string, data> decode(const std::string& str) {
    size_t pos = str.rfind(separator);
    if (str.size() > 90 || pos == std::string::npos || pos < 1 || pos + 7 > str.size()) {
        return std::make_pair("", data());
    }
    int32_t chk = checksum_str(str.begin() + pos + 1, str.end(), str.begin(), str.begin() + pos);
    if (chk == -1) {
        return std::make_pair("", data());
    }
    std::string hrp;
    hrp.resize(pos);
    for (unsigned int i = 0; i < pos; ++i) {
        hrp[i] = to_lc(str[i]);
    }
    data ret;
    ret.resize(str.size() - 7 - pos);
    for (size_t i = pos + 1; i < str.size() - 6; ++i) {
        ret[i - pos - 1] = charset_rev[(unsigned char)str[i]];
    }
    return std::make_pair(hrp, ret);
}

}
