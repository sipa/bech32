#ifndef _SEGWIT_ADDR_H_
#define _SEGWIT_ADDR_H_ 1

#include <stdint.h>

int bech32_decode(
    size_t *hrp_len,
    uint8_t *data,
    size_t *data_len,
    const char *input
);

int segwit_addr_encode(
    char *output,
    const char *hrp,
    uint8_t witver,
    const uint8_t *witprog,
    size_t witprog_len
);

int segwit_addr_decode(
    int* witver,
    uint8_t* witprog,
    size_t* witprog_len,
    const char* hrp,
    const char* addr
);

#endif
