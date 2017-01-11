/*
 * HMAC-SHA-224/256/384/512 implementation
 * Last update: 06/15/2005
 * Issue date:  06/15/2005
 *
 * Copyright (C) 2005 Olivier Gay <olivier.gay@a3.epfl.ch>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <string.h>

#include "hmac_sha2.h"

/* HMAC-SHA-256 functions */

void hmac_sha256_init(hmac_sha256_ctx *ctx, const unsigned char *key,
                      unsigned int key_size)
{
    unsigned int fill;
    unsigned int num;

    const unsigned char *key_used;
    unsigned char key_temp[SHA256_DIGEST_SIZE];
    int i;

    if (key_size == SHA256_BLOCK_SIZE) {
        key_used = key;
        num = SHA256_BLOCK_SIZE;
    } else {
        if (key_size > SHA256_BLOCK_SIZE){
            num = SHA256_DIGEST_SIZE;
<<<<<<< Updated upstream
            sha256(key, key_size, key_temp, SHA256_DIGEST_SIZE);
=======
#if ((CIPHMODE == 0) || (CIPHMODE == 1))
            sha256(key, key_size, key_temp, SHA256_DIGEST_SIZE);
#elif CIPHMODE == 2
            sha256_hw(key, key_size, key_temp, SHA256_DIGEST_SIZE);
            printf("doang1 \n");
#endif
>>>>>>> Stashed changes
            key_used = key_temp;
        } else { /* key_size > SHA256_BLOCK_SIZE */
            key_used = key;
            num = key_size;
        }
        fill = SHA256_BLOCK_SIZE - num;
        memset(ctx->block_ipad + num, 0x36, fill);
        memset(ctx->block_opad + num, 0x5c, fill);
    }
    //printf("log5 \n");
    for (i = 0; i < (int) num; i++) {
        ctx->block_ipad[i] = key_used[i] ^ 0x36;
        ctx->block_opad[i] = key_used[i] ^ 0x5c;
    }
    //printf("log6 \n");
    sha256_init(&ctx->ctx_inside);
    printf("doang2 \n");
    //printf("log7 \n");
#if ((CIPHMODE == 0) || (CIPHMODE == 1))
    sha256_update(&ctx->ctx_inside, ctx->block_ipad, SHA256_BLOCK_SIZE);
#elif CIPHMODE == 2
    sha256_process(&ctx->ctx_inside, ctx->block_ipad, SHA256_BLOCK_SIZE);
    printf("doang3 \n");
#endif
    sha256_init(&ctx->ctx_outside);
    printf("doang4 \n");

#if ((CIPHMODE == 0) || (CIPHMODE == 1))
    sha256_update(&ctx->ctx_outside, ctx->block_opad,
                  SHA256_BLOCK_SIZE);
#elif CIPHMODE == 2
    //printf("log10 \n");
    sha256_process(&ctx->ctx_outside, ctx->block_opad,
                  SHA256_BLOCK_SIZE);
    printf("doang5 \n");
#endif
    /* for hmac_reinit */
    memcpy(&ctx->ctx_inside_reinit, &ctx->ctx_inside,
           sizeof(sha256_ctx));
    memcpy(&ctx->ctx_outside_reinit, &ctx->ctx_outside,
           sizeof(sha256_ctx));
}

void hmac_sha256_reinit(hmac_sha256_ctx *ctx)
{
    memcpy(&ctx->ctx_inside, &ctx->ctx_inside_reinit,
           sizeof(sha256_ctx));
    memcpy(&ctx->ctx_outside, &ctx->ctx_outside_reinit,
           sizeof(sha256_ctx));
}

void hmac_sha256_update(hmac_sha256_ctx *ctx, const unsigned char *message,
                        unsigned int message_len)
{
#if ((CIPHMODE == 0) || (CIPHMODE == 1))
    sha256_update(&ctx->ctx_inside, message, message_len);
#elif CIPHMODE == 2
    sha256_process(&ctx->ctx_inside, message, message_len);
    printf("doang6 \n");
#endif
}

void hmac_sha256_final(hmac_sha256_ctx *ctx, unsigned char *mac,
                       unsigned int mac_size)
{
    unsigned char digest_inside[SHA256_DIGEST_SIZE];
    unsigned char mac_temp[SHA256_DIGEST_SIZE];
    //printf("log14 \n");
#if ((CIPHMODE == 0) || (CIPHMODE == 1))
    sha256_final(&ctx->ctx_inside, digest_inside);
    sha256_update(&ctx->ctx_outside, digest_inside, SHA256_DIGEST_SIZE);
    sha256_final(&ctx->ctx_outside, mac_temp);
#elif CIPHMODE == 2
    //printf("log15 \n");
    sha256_done(&ctx->ctx_inside, digest_inside);
    printf("doang7 \n");
    //printf("log16 \n");
    sha256_process(&ctx->ctx_outside, digest_inside, SHA256_DIGEST_SIZE);
    printf("doang8 \n");
    //printf("log1 \n");
    sha256_done(&ctx->ctx_outside, mac_temp);
    printf("doang9 \n");
#endif
    memcpy(mac, mac_temp, mac_size);
}

void hmac_sha256(const unsigned char *key, unsigned int key_size,
          const unsigned char *message, unsigned int message_len,
          unsigned char *mac, unsigned mac_size)
{
    hmac_sha256_ctx ctx;
#if CIPHMODE == 2
    crypto_init();
#endif

    hmac_sha256_init(&ctx, key, key_size);
    /*
    uint8_t i;
      printf("Before HMAC Message: ");
      for (i = 0; i < message_len; i++)
        printf("%02x", *message++);
      printf("\n");

      printf("Before HMAC MAC: ");
      for (i = 0; i < mac_size; i++)
        printf("%02x", *mac++);
      printf("\n");*/

    hmac_sha256_update(&ctx, message, message_len);
    /*
    printf("On-going HMAC Message: ");
    for (i = 0; i < message_len; i++)
      printf("%02x", *message++);
    printf("\n");

    printf("On-going HMAC MAC: ");
    for (i = 0; i < mac_size; i++)
      printf("%02x", *mac++);
    printf("\n");*/
    hmac_sha256_final(&ctx, mac, mac_size);
    /*
    printf("After HMAC Message: ");
    for (i = 0; i < message_len; i++)
      printf("%02x", *message++);
    printf("\n");

    printf("After HMAC MAC: ");
    for (i = 0; i < mac_size; i++)
      printf("%02x", *mac++);
    printf("\n"); */
}

