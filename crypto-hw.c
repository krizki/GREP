#include "crypto-hw.h"

#define LPM_PERIPH_PERMIT_PM1_FUNCS_MAX 5
#define AES_KEY_AREAS   				8
#define MAXBUFSIZE						300

typedef bool (*lpm_periph_permit_pm1_func_t)(void);

static lpm_periph_permit_pm1_func_t periph_permit_pm1_funcs[LPM_PERIPH_PERMIT_PM1_FUNCS_MAX];

/*---------------------------------------------------------------------------*/
void lpm_register_peripheral(lpm_periph_permit_pm1_func_t permit_pm1_func)
//void lpm_register_peripheral(bool permit_pm1_func)
{
  int i;

  for(i = 0; i < LPM_PERIPH_PERMIT_PM1_FUNCS_MAX; i++) {
    if(periph_permit_pm1_funcs[i] == permit_pm1_func) {
      break;
    } else if(periph_permit_pm1_funcs[i] == NULL) {
      periph_permit_pm1_funcs[i] = permit_pm1_func;
      break;
    }
  }
}
/*---------------------------------------------------------------------------*/
static bool permit_pm1(void)
{
  return REG(AES_CTRL_ALG_SEL) == 0;
}
/* -------------------------------------------------------------------------- */
void crypto_init(void)
{
  volatile int i;

  lpm_register_peripheral(permit_pm1);

  crypto_enable();

  /* Reset the AES/SHA cryptoprocessor */
  REG(SYS_CTRL_SRSEC) |= SYS_CTRL_SRSEC_AES;
  for(i = 0; i < 16; i++);
  REG(SYS_CTRL_SRSEC) &= ~SYS_CTRL_SRSEC_AES;
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

  return AES_SUCCESS;
}
/*---------------------------------------------------------------------------*/
uint8_t
aes_load_keys(const void *keys, uint8_t key_size, uint8_t count, uint8_t start_area)
{
  uint32_t aes_key_store_size;
  uint32_t areas;
  uint64_t aligned_keys[AES_KEY_AREAS * 128 / 8 / sizeof(uint64_t)];
  int i;

  if(REG(AES_CTRL_ALG_SEL) != 0x00000000) {
    return CRYPTO_RESOURCE_IN_USE;
  }

  /* 192-bit keys must be padded to 256 bits */
  if(key_size == AES_KEY_STORE_SIZE_KEY_SIZE_192) {
    for(i = 0; i < count; i++) {
      memcpy(&aligned_keys[i << 2], &((const uint64_t *)keys)[i * 3], 192 / 8);
      aligned_keys[(i << 2) + 3] = 0;
    }
  }

  /* Change count to the number of 128-bit key areas */
  if(key_size != AES_KEY_STORE_SIZE_KEY_SIZE_128) {
    count <<= 1;
  }

  /* The keys base address needs to be 4-byte aligned */
  if(key_size != AES_KEY_STORE_SIZE_KEY_SIZE_192) {
    memcpy(aligned_keys, keys, count << 4);
  }

  /* Workaround for AES registers not retained after PM2 */
  REG(AES_CTRL_INT_CFG) = AES_CTRL_INT_CFG_LEVEL;
  REG(AES_CTRL_INT_EN) = AES_CTRL_INT_EN_DMA_IN_DONE |
                         AES_CTRL_INT_EN_RESULT_AV;

  /* Configure master control module */
  REG(AES_CTRL_ALG_SEL) = AES_CTRL_ALG_SEL_KEYSTORE;

  /* Clear any outstanding events */
  REG(AES_CTRL_INT_CLR) = AES_CTRL_INT_CLR_DMA_IN_DONE |
                          AES_CTRL_INT_CLR_RESULT_AV;

  /* Configure key store module (areas, size)
   * Note that writing AES_KEY_STORE_SIZE deletes all stored keys */
  aes_key_store_size = REG(AES_KEY_STORE_SIZE);
  if((aes_key_store_size & AES_KEY_STORE_SIZE_KEY_SIZE_M) != key_size) {
    REG(AES_KEY_STORE_SIZE) = (aes_key_store_size &
                               ~AES_KEY_STORE_SIZE_KEY_SIZE_M) | key_size;
  }

  /* Free possibly already occupied key areas */
  areas = ((0x00000001 << count) - 1) << start_area;
  REG(AES_KEY_STORE_WRITTEN_AREA) = areas;

  /* Enable key areas to write */
  REG(AES_KEY_STORE_WRITE_AREA) = areas;

  /* Configure DMAC
   * Enable DMA channel 0 */
  REG(AES_DMAC_CH0_CTRL) = AES_DMAC_CH_CTRL_EN;

  /* Base address of the keys in ext. memory */
  REG(AES_DMAC_CH0_EXTADDR) = (uint32_t)aligned_keys;

  /* Total keys length in bytes (e.g. 16 for 1 x 128-bit key) */
  REG(AES_DMAC_CH0_DMALENGTH) = (REG(AES_DMAC_CH0_DMALENGTH) &
                                 ~AES_DMAC_CH_DMALENGTH_DMALEN_M) |
                                (count << (4 + AES_DMAC_CH_DMALENGTH_DMALEN_S));

  /* Wait for operation to complete */
  while(!(REG(AES_CTRL_INT_STAT) & AES_CTRL_INT_STAT_RESULT_AV));

  /* Check for absence of errors in DMA and key store */
  if(REG(AES_CTRL_INT_STAT) & AES_CTRL_INT_STAT_DMA_BUS_ERR) {
    REG(AES_CTRL_INT_CLR) = AES_CTRL_INT_CLR_DMA_BUS_ERR;
    /* Disable master control / DMA clock */
    REG(AES_CTRL_ALG_SEL) = 0x00000000;
    return AES_DMA_BUS_ERROR;
  }
  if(REG(AES_CTRL_INT_STAT) & AES_CTRL_INT_STAT_KEY_ST_WR_ERR) {
    REG(AES_CTRL_INT_CLR) = AES_CTRL_INT_CLR_KEY_ST_WR_ERR;
    /* Disable master control / DMA clock */
    REG(AES_CTRL_ALG_SEL) = 0x00000000;
    return AES_KEYSTORE_WRITE_ERROR;
  }

  /* Acknowledge the interrupt */
  REG(AES_CTRL_INT_CLR) = AES_CTRL_INT_CLR_DMA_IN_DONE |
                          AES_CTRL_INT_CLR_RESULT_AV;

  /* Disable master control / DMA clock */
  REG(AES_CTRL_ALG_SEL) = 0x00000000;

  /* Check status, if error return error code */
  if((REG(AES_KEY_STORE_WRITTEN_AREA) & areas) != areas) {
    return AES_KEYSTORE_WRITE_ERROR;
  }

  return AES_SUCCESS;
}
/* -------------------------------------------------------------------------- */
void aes256_decrypt_cbc_hw(uint8_t *buf, uint8_t len_buf, uint8_t *key, uint8_t *out)
{
	crypto_init();

	uint8_t key_area = 0;
	uint8_t ret;

    ret = aes_load_keys(key, AES_KEY_STORE_SIZE_KEY_SIZE_256, 1, 0);
    //while(ret);
    //ret = aes_load_key(key, 0);
    //printf("ret %d \n", ret);
    //if (ret != 0) return;
    //PROCESS_PAUSE();
    ret = cbc_auth_encrypt_start_hw(key_area, buf, len_buf);
    //while(ret);
    //if (ret != 0) return;
    printf("ret %d \n", ret);
    memcpy(out, buf, len_buf * sizeof(uint8_t));

    crypto_disable();
} /* aes256_decrypt_cbc_hw */

