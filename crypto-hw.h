#include "contiki.h"
#include "contiki-conf.h"
#include "dev/cc2538-crypto.h"
#include "dev/cc2538-sha2.h"
#include "dev/sys-ctrl.h"

#include <stdbool.h>
#include <stdio.h>


//void lpm_register_peripheral(bool permit_pm1_func);
void crypto_init(void);
void sha256_hw(const unsigned char *message, unsigned int len, unsigned char *digest, unsigned int digest_len);
uint8_t cbc_auth_encrypt_start_hw(uint8_t key_area, void *pdata, uint16_t pdata_len);
uint8_t aes_load_keys(const void *keys, uint8_t key_size, uint8_t count, uint8_t start_area);
void aes256_decrypt_cbc_hw(uint8_t *buf, uint8_t len_buf, uint8_t *key, uint8_t *out);
