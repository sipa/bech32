#ifndef _SEGWIT_ADDR_H_
#define _SEGWIT_ADDR_H_ 1

#include <stdint.h>

uint32_t bech32_polymod_step(uint32_t pre);
int bech32_encode(char *output, const char *hrp, const uint8_t *data, size_t data_len);
int32_t bech32_decode_fault(size_t *hrp_len, uint8_t *data, size_t *data_len, const char *input);
int bech32_decode(size_t *hrp_len, uint8_t *data, size_t *data_len, const char *input);
int segwit_addr_encode(char *output, const char *hrp, uint8_t witver, const uint8_t *witprog, size_t witprog_len);
int segwit_addr_decode(int* witver, uint8_t* witdata, size_t* witdata_len, const char* hrp, const char* addr);

#endif
