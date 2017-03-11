#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "segwit_addr.h"

uint32_t bech32_polymod_step(uint32_t pre) {
    uint8_t b = pre >> 25;
    return ((pre & 0x1FFFFFF) << 5) ^
        (-((b >> 0) & 1) & 0x3b6a57b2UL) ^
        (-((b >> 1) & 1) & 0x26508e6dUL) ^
        (-((b >> 2) & 1) & 0x1ea119faUL) ^
        (-((b >> 3) & 1) & 0x3d4233ddUL) ^
        (-((b >> 4) & 1) & 0x2a1462b3UL);
}

static const char* charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static const int8_t charset_rev[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
};

int bech32_encode(char *output, const char *hrp, const uint8_t *data, size_t data_len) {
    uint32_t chk = 1;
    size_t i = 0;
    while (hrp[i] != 0) {
        if (!(hrp[i] >> 5)) return 0;
        chk = bech32_polymod_step(chk) ^ (hrp[i] >> 5);
        ++i;
    }
    if (i + 7 + data_len > 90) return 0;
    chk = bech32_polymod_step(chk);
    while (*hrp != 0) {
        chk = bech32_polymod_step(chk) ^ (*hrp & 0x1f);
        *(output++) = *(hrp++);
    }
    *(output++) = '1';
    for (i = 0; i < data_len; ++i) {
        if (*data >> 5) return 0;
        chk = bech32_polymod_step(chk) ^ (*data);
        *(output++) = charset[*(data++)];
    }
    for (i = 0; i < 6; ++i) {
        chk = bech32_polymod_step(chk);
    }
    chk ^= 1;
    for (i = 0; i < 6; ++i) {
        *(output++) = charset[(chk >> ((5 - i) * 5)) & 0x1f];
    }
    *output = 0;
    return 1;
}

int32_t bech32_decode_fault(size_t *hrp_len, uint8_t *data, size_t *data_len, const char *input) {
    uint32_t chk = 1;
    size_t i;
    size_t input_len = strlen(input);
    if (input_len < 8 || input[input_len] != 0) {
        return -1;
    }
    *data_len = 0;
    while (*data_len < input_len && input[(input_len - 1) - *data_len] != '1') {
        ++(*data_len);
    }
    *hrp_len = input_len - (1 + *data_len);
    if (*hrp_len < 1 || *data_len < 6) {
        return -2;
    }
    *(data_len) -= 6;
    for (i = 0; i < *hrp_len; ++i) {
        if (input[i] < 33 || input[i] > 126) {
            return -3;
        }
        chk = bech32_polymod_step(chk) ^ (input[i] >> 5);
    }
    chk = bech32_polymod_step(chk);
    for (i = 0; i < *hrp_len; ++i) {
        chk = bech32_polymod_step(chk) ^ (input[i] & 0x1f);
    }
    ++i;
    while (i < input_len) {
        int v = (input[i] & 0x80) ? -2 : charset_rev[(int)input[i]];
        if (v == -1) {
            return -4;
        }
        if (v == -2) {
            return -5;
        }
        chk = bech32_polymod_step(chk) ^ v;
        if (i + 6 < input_len) {
            data[i - (1 + *hrp_len)] = v;
        }
        ++i;
    }
    return chk ^ 1;
}

int bech32_decode(size_t *hrp_len, uint8_t *data, size_t *data_len, const char *input) {
    return bech32_decode_fault(hrp_len, data, data_len, input) == 0;
}

static int convert_bits(uint8_t* out, size_t* outlen, int outbits, const uint8_t* in, size_t inlen, int inbits, int pad) {
    uint32_t val = 0;
    int bits = 0;
    uint32_t maxv = (((uint32_t)1) << outbits) - 1;
    while (inlen--) {
        val = (val << inbits) | *(in++);
        bits += inbits;
        while (bits >= outbits) {
            bits -= outbits;
            out[(*outlen)++] = (val >> bits) & maxv;
        }
    }
    if (pad) {
        if (bits) {
            out[(*outlen)++] = (val << (outbits - bits)) & maxv;
        }
    } else if (((val << (outbits - bits)) & maxv) || bits >= inbits) {
        return 0;
    }
    return 1;
}

int segwit_addr_encode(char *output, const char *hrp, uint8_t witver, const uint8_t *witprog, size_t witprog_len) {
    uint8_t data[65];
    size_t datalen = 0;
    if (witver > 16) return 0;
    if (witver == 0 && witprog_len != 20 && witprog_len != 32) return 0;
    if (witprog_len < 2 || witprog_len > 40) return 0;
    data[0] = witver;
    convert_bits(data + 1, &datalen, 5, witprog, witprog_len, 8, 1);
    ++datalen;
    return bech32_encode(output, hrp, data, datalen);
}

int segwit_addr_decode_fault(int* witver, uint8_t* witdata, size_t* witdata_len, const char* hrp, const char* addr, int32_t* fault) {
    uint8_t data[84];
    char addr_lower[93];
    size_t data_len;
    size_t hrp_len;
    size_t pos = 0;
    int have_lower = 0;
    int have_upper = 0;
    int32_t faultv;
    while (pos < 93) {
        char ch = addr[pos];
        if (ch >= 'A' && ch <= 'Z') {
            have_upper = 1;
            ch = (ch - 'A') + 'a';
        } else if (ch >= 'a' && ch <= 'z') {
            have_lower = 1;
        }
        addr_lower[pos] = ch;
        if (ch == 0) break;
        ++pos;
    }
    if (pos == 93) return 0;
    if (have_lower && have_upper) return 0;
    faultv = bech32_decode_fault(&hrp_len, data, &data_len, addr_lower);
    if (fault) *fault = faultv;
    if (faultv < 0) return 0;
    if (data_len == 0 || data_len > 65) return 0;
    if (strlen(hrp) != hrp_len) return 0;
    if (memcmp(hrp, addr_lower, hrp_len) != 0) return 0;
    if (data[0] > 16) return 0;
    *witdata_len = 0;
    if (!convert_bits(witdata, witdata_len, 8, data + 1, data_len - 1, 5, 0)) return 0;
    if (*witdata_len < 2 || *witdata_len > 40) return 0;
    if (data[0] == 0 && *witdata_len != 20 && *witdata_len != 32) return 0;
    *witver = data[0];
    return 1;
}

int segwit_addr_decode(int* witver, uint8_t* witdata, size_t* witdata_len, const char* hrp, const char* addr) {
    int32_t fault;
    return segwit_addr_decode_fault(witver, witdata, witdata_len, hrp, addr, &fault) && fault == 0;
}
