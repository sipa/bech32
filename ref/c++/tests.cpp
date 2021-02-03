/* Copyright (c) 2017, 2021 Pieter Wuille
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

#include <stdio.h>
#include <string.h>

#include <algorithm>

#include "segwit_addr.h"
#include "bech32.h"

static const std::string valid_checksum_bech32[] = {
    "A12UEL5L",
    "a12uel5l",
    "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
    "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
    "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
    "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
    "?1ezyfcl",
};

static const std::string valid_checksum_bech32m[] = {
    "A1LQFN3A",
    "a1lqfn3a",
    "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
    "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
    "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
    "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
    "?1v759aa",
};

static const std::string invalid_checksum_bech32[] = {
    " 1nwldj5",
    "\x7f""1axkwrx",
    "\x80""1eym55h",
    "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
    "pzry9x0s0muk",
    "1pzry9x0s0muk",
    "x1b4n0q5v",
    "li1dgmt3",
    "de1lg7wt\xff",
    "A1G7SGD8",
    "10a06t8",
    "1qzzfhee",
};

static const std::string invalid_checksum_bech32m[] = {
    " 1xj0phk",
    "\x7F""1g6xzxy",
    "\x80""1vctc34",
    "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
    "qyrz8wqd2c9m",
    "1qyrz8wqd2c9m",
    "y1b0jsk6g",
    "lt1igcx5c0",
    "in1muywd",
    "mm1crxm3i",
    "au1s5cgom",
    "M1VUXWEZ",
    "16plkw9",
    "1p2gdwpf",
};

struct valid_address_data {
    const std::string address;
    const std::vector<uint8_t> scriptPubKey;
};

struct invalid_address_data {
    const std::string hrp;
    int version;
    size_t program_length;
};

static const struct valid_address_data valid_address[] = {
    {
        "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
        {{
            0x00, 0x14, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
            0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6
        }}
    },
    {
        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
        {{
            0x00, 0x20, 0x18, 0x63, 0x14, 0x3c, 0x14, 0xc5, 0x16, 0x68, 0x04,
            0xbd, 0x19, 0x20, 0x33, 0x56, 0xda, 0x13, 0x6c, 0x98, 0x56, 0x78,
            0xcd, 0x4d, 0x27, 0xa1, 0xb8, 0xc6, 0x32, 0x96, 0x04, 0x90, 0x32,
            0x62
        }}
    },
    {
        "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
        {{
            0x51, 0x28, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
            0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
            0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c,
            0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6
        }}
    },
    {
        "BC1SW50QGDZ25J",
        {{
           0x60, 0x02, 0x75, 0x1e
        }}
    },
    {
        "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
        {{
            0x52, 0x10, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
            0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23
        }}
    },
    {
        "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
        {{
            0x00, 0x20, 0x00, 0x00, 0x00, 0xc4, 0xa5, 0xca, 0xd4, 0x62, 0x21,
            0xb2, 0xa1, 0x87, 0x90, 0x5e, 0x52, 0x66, 0x36, 0x2b, 0x99, 0xd5,
            0xe9, 0x1c, 0x6c, 0xe2, 0x4d, 0x16, 0x5d, 0xab, 0x93, 0xe8, 0x64,
            0x33
        }}
    },
    {
        "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
        {{
            0x51, 0x20, 0x00, 0x00, 0x00, 0xc4, 0xa5, 0xca, 0xd4, 0x62, 0x21,
            0xb2, 0xa1, 0x87, 0x90, 0x5e, 0x52, 0x66, 0x36, 0x2b, 0x99, 0xd5,
            0xe9, 0x1c, 0x6c, 0xe2, 0x4d, 0x16, 0x5d, 0xab, 0x93, 0xe8, 0x64,
            0x33
        }}
    },
    {
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
        {{
            0x51, 0x20, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55,
            0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb,
            0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
            0x98
        }}
    },
};

static const std::string invalid_address[] = {
    "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
    "tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf",
    "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL",
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
    "tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47",
    "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
    "BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
    "bc1pw5dgrnzv",
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav",
    "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
    "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
    "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
    "bc1gmk9yu",
};

static const invalid_address_data invalid_address_enc[] = {
    {"bc", 0, 21},
    {"bc", 17, 32},
    {"bc", 1, 1},
    {"bc", 16, 41},
};

static std::vector<uint8_t> segwit_scriptpubkey(int witver, const std::vector<uint8_t>& witprog) {
    std::vector<uint8_t> ret;
    ret.push_back(witver ? (0x50 + witver) : 0);
    ret.push_back(witprog.size());
    ret.insert(ret.end(), witprog.begin(), witprog.end());
    return ret;
}

bool case_insensitive_equal(const std::string& s1, const std::string& s2) {
    size_t i = 0;
    if (s1.size() != s2.size()) return false;
    while (i < s1.size() && i < s2.size()) {
        char c1 = s1[i];
        char c2 = s2[i];
        if (c1 >= 'A' && c1 <= 'Z') c1 = (c1 - 'A') + 'a';
        if (c2 >= 'A' && c2 <= 'Z') c2 = (c2 - 'A') + 'a';
        if (c1 != c2) return false;
        ++i;
    }
    return true;
}

int main(void) {
    int fail = 0;
    for (const auto& input : valid_checksum_bech32) {
        bool ok = true;
        const auto dec = bech32::decode(input);
        if (dec.encoding != bech32::Encoding::BECH32) {
            fprintf(stderr, "Failed to parse '%s'\n", input.c_str());
            ok = false;
        }
        if (ok) {
            std::string recode = bech32::encode(dec.hrp, dec.data, bech32::Encoding::BECH32);
            if (recode.empty()) {
                fprintf(stderr, "Failed to encode '%s'\n", input.c_str());
            } else {
               ok = case_insensitive_equal(recode, input);
               if (!ok) fprintf(stderr, "Failed to roundtrip '%s' -> '%s'\n", input.c_str(), recode.c_str());
            }
        }
        fail += !ok;
    }
    for (const auto& input : invalid_checksum_bech32) {
        const auto dec = bech32::decode(input);
        if (dec.encoding == bech32::Encoding::BECH32) {
            fprintf(stderr, "Parsed an invalid code: '%s'\n", input.c_str());
            ++fail;
        }
    }
    for (const auto& input : valid_checksum_bech32m) {
        bool ok = true;
        const auto dec = bech32::decode(input);
        if (dec.encoding != bech32::Encoding::BECH32M) {
            fprintf(stderr, "Failed to parse '%s'\n", input.c_str());
            ok = false;
        }
        if (ok) {
            std::string recode = bech32::encode(dec.hrp, dec.data, bech32::Encoding::BECH32M);
            if (recode.empty()) {
                fprintf(stderr, "Failed to encode '%s'\n", input.c_str());
            } else {
               ok = case_insensitive_equal(recode, input);
               if (!ok) fprintf(stderr, "Failed to roundtrip '%s' -> '%s'\n", input.c_str(), recode.c_str());
            }
        }
        fail += !ok;
    }
    for (const auto& input : invalid_checksum_bech32m) {
        const auto dec = bech32::decode(input);
        if (dec.encoding == bech32::Encoding::BECH32M) {
            fprintf(stderr, "Parsed an invalid code: '%s'\n", input.c_str());
            ++fail;
        }
    }
    for (const auto& input : valid_address) {
        std::string hrp = "bc";
        auto dec = segwit_addr::decode(hrp, input.address);
        if (dec.first == -1) {
            hrp = "tb";
            dec = segwit_addr::decode(hrp, input.address);
        }
        bool ok = true;
        if (dec.first == -1) {
            ok = false;
            fprintf(stderr, "Failed to segwit_addr::decode '%s'\n", input.address.c_str());
        }
        if (ok) {
            std::vector<uint8_t> spk = segwit_scriptpubkey(dec.first, dec.second);
            ok = spk == input.scriptPubKey;
            if (!ok) {
                fprintf(stderr, "segwit_addr::decode produces wrong result: '%s'\n", input.address.c_str());
            }
        }
        if (ok) {
            std::string recode = segwit_addr::encode(hrp, dec.first, dec.second);
            if (recode.empty()) {
                fprintf(stderr, "segwit_addr::encode fails on '%s'\n", input.address.c_str());
                ok = false;
            }
            if (ok) {
                ok = case_insensitive_equal(input.address, recode);
                if (!ok) fprintf(stderr, "segwit_addr::encode roundtrip fails: '%s' -> '%s'\n", input.address.c_str(), recode.c_str());
            }
        }
        fail += !ok;
    }
    for (const auto& input : invalid_address) {
        auto dec = segwit_addr::decode("bc", input);
        bool ok = true;
        if (dec.first != -1) {
            printf("segwit_addr::decode succeeds on invalid '%s'\n", input.c_str());
            ok = false;
        }
        dec = segwit_addr::decode("tb", input);
        if (dec.first != -1) {
            printf("segwit_addr::decode succeeds on invalid '%s'\n", input.c_str());
            ok = false;
        }
        fail += !ok;
    }
    for (const auto& input : invalid_address_enc) {
        std::string code = segwit_addr::encode(input.hrp, input.version, std::vector<uint8_t>(input.program_length, 0));
        if (!code.empty()) {
            printf("segwit_addr::encode succeeds on invalid '%s'\n", code.c_str());
            ++fail;
        }
    }
    printf("%i failures\n", fail);
    return fail != 0;
}
