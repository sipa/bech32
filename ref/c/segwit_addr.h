#ifndef _SEGWIT_ADDR_H_
#define _SEGWIT_ADDR_H_ 1

#include <stdint.h>

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

/** Encode a Bech32 string
 *
 *  Out: output:  Pointer to a buffer of size strlen(hrp) + data_len + 8.
 *                Will be updated to contain the null-terminated Bech32 string.
 *  In: hrp :     Pointer to the null-terminated human readable part.
 *      data :    Pointer to an array of 5-bit values.
 *      data_len: Length of the data array.
 *  Returns 1 if succesful.
 */
int bech32_encode(
    char *output,
    const char *hrp,
    const uint8_t *data,
    size_t data_len
);

/** Decode a Bech32 string
 *
 *  Out: hrp_len:  Pointer to a size_t that will be updated to be the length
 *                 of the prefix of the input that is the human readable part.
 *       data:     Pointer to a buffer of size strlen(input) - 8 that will
 *                 hold the encoded 5-bit data values.
 *       data_len: Pointer to a size_t that will be updated to be the number
 *                 of entries in data.
 *  In: input:     Pointer to a null-terminated Bech32 string.
 *  Returns 1 if succesful.
 */
int bech32_decode(
    char *hrp,
    uint8_t *data,
    size_t *data_len,
    const char *input
);

#endif
