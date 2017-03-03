#include "crypto-hw.h"

#define LPM_PERIPH_PERMIT_PM1_FUNCS_MAX 5
#define AES_KEY_AREAS   				8
#define MAXBUFSIZE						300

typedef bool (*lpm_periph_permit_pm1_func_t)(void);

static lpm_periph_permit_pm1_func_t periph_permit_pm1_funcs[LPM_PERIPH_PERMIT_PM1_FUNCS_MAX];

/*---------------------------------------------------------------------------*/
static bool permit_pm1(void)
{
  return REG(AES_CTRL_ALG_SEL) == 0;
}
/*---------------------------------------------------------------------------*/
void sha256_hw(const unsigned char *message, unsigned int len, unsigned char *digest, unsigned int digest_len)
{
  static sha256_state_t state;

  crypto_init();

  sha256_init(&state);
  sha256_process(&state, message, len);
  sha256_done(&state, digest);

  //crypto_disable();
}

/* -------------------------------------------------------------------------- */
uint8_t cbc_auth_encrypt_start_hw(uint8_t key_area, void *pdata, uint16_t pdata_len)
{
  uint32_t iv[4] = {0x33323130, 0x37363534, 0x31303938, 0x35343332}; // Different Endian with KM

  /* Workaround for AES registers not retained after PM2 */
  REG(AES_CTRL_INT_CFG) = AES_CTRL_INT_CFG_LEVEL;
  REG(AES_CTRL_INT_EN) = AES_CTRL_INT_EN_DMA_IN_DONE |
                         AES_CTRL_INT_EN_RESULT_AV;

  REG(AES_CTRL_ALG_SEL) = AES_CTRL_ALG_SEL_AES;
  REG(AES_CTRL_INT_CLR) = AES_CTRL_INT_CLR_DMA_IN_DONE |
                          AES_CTRL_INT_CLR_RESULT_AV;

  REG(AES_KEY_STORE_READ_AREA) = key_area;

  /* Wait until key is loaded to the AES module */
  while(REG(AES_KEY_STORE_READ_AREA) & AES_KEY_STORE_READ_AREA_BUSY);

  /* Check for Key Store read error */
  if(REG(AES_CTRL_INT_STAT) & AES_CTRL_INT_STAT_KEY_ST_RD_ERR) {
    /* Clear the Keystore Read error bit */
    REG(AES_CTRL_INT_CLR) = AES_CTRL_INT_CLR_KEY_ST_RD_ERR;
    return AES_KEYSTORE_READ_ERROR;
  }

  /* Write initialization vector */
  REG(AES_AES_IV_0) = iv[0];
  REG(AES_AES_IV_1) = iv[1];
  REG(AES_AES_IV_2) = iv[2];
  REG(AES_AES_IV_3) = iv[3];

  /* Program AES-CCM-128 encryption */
  REG(AES_AES_CTRL) = AES_AES_CTRL_SAVE_CONTEXT |            /* Save context */
    AES_AES_CTRL_CBC;                                       /* CBC */

  /* Write the length of the crypto block (lo) */
  REG(AES_AES_C_LENGTH_0) = pdata_len;
  /* Write the length of the crypto block (hi) */
  REG(AES_AES_C_LENGTH_1) = 0;

  /* Clear interrupt status */
  REG(AES_CTRL_INT_CLR) = AES_CTRL_INT_CLR_DMA_IN_DONE |
                          AES_CTRL_INT_CLR_RESULT_AV;

  /* Enable result available bit in interrupt enable */
  REG(AES_CTRL_INT_EN) = AES_CTRL_INT_EN_RESULT_AV;

  if(pdata_len != 0) {
    /* Configure DMAC
     * Enable DMA channel 0 */
    REG(AES_DMAC_CH0_CTRL) = AES_DMAC_CH_CTRL_EN;
    /* Base address of the payload data in ext. memory */
    REG(AES_DMAC_CH0_EXTADDR) = (uint32_t)pdata;
    /* Payload data length in bytes */
    REG(AES_DMAC_CH0_DMALENGTH) = pdata_len;

    /* Enable DMA channel 1 */
    REG(AES_DMAC_CH1_CTRL) = AES_DMAC_CH_CTRL_EN;
    /* Base address of the output data buffer */
    REG(AES_DMAC_CH1_EXTADDR) = (uint32_t)pdata;
    /* Output data length in bytes */
    REG(AES_DMAC_CH1_DMALENGTH) = pdata_len;
  }

  /* Wait for completion of the operation */
  while(!(REG(AES_CTRL_INT_STAT) & AES_CTRL_INT_STAT_RESULT_AV));

  return CRYPTO_SUCCESS;
}
/* -------------------------------------------------------------------------- */
void aes256_decrypt_cbc_hw(uint8_t *buf, uint8_t len_buf, uint8_t *key, uint8_t *out)
{
	crypto_init();

	uint8_t key_area = 0;
	uint8_t ret;

    ret = aes_load_keys(key, AES_KEY_STORE_SIZE_KEY_SIZE_256, 1, 0);

    if (ret != CRYPTO_SUCCESS) return;
    ret = cbc_auth_encrypt_start_hw(key_area, buf, len_buf);

    if (ret != CRYPTO_SUCCESS) return;
    memcpy(out, buf, len_buf * sizeof(uint8_t));

    crypto_disable();
} /* aes256_decrypt_cbc_hw */

