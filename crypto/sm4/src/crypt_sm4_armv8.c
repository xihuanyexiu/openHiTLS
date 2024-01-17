/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SM4

#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_sm4.h"
#include "crypt_sm4_armv8.h"

int32_t CRYPT_SM4_SetEncryptKey(CRYPT_SM4_Ctx *ctx, const uint8_t *key, uint32_t len)
{
    if (len != SM4_KEY_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM4_KEYLEN_ERROR);
        return CRYPT_SM4_KEYLEN_ERROR;
    }
    Vpsm4SetEncryptKey(key, (SM4_KEY *)ctx->rk);

    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM4_SetDecryptKey(CRYPT_SM4_Ctx *ctx, const uint8_t *key, uint32_t len)
{
    if (len != SM4_KEY_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM4_KEYLEN_ERROR);
        return CRYPT_SM4_KEYLEN_ERROR;
    }

    Vpsm4SetDecryptKey(key, (SM4_KEY *)ctx->rk);
    return CRYPT_SUCCESS;
}

#ifdef HITLS_CRYPTO_CBC
int32_t CRYPT_SM4_CBC_Encrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv)
{
    if (len < CRYPT_SM4_BLOCKSIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM4_DATALEN_ERROR);
        return CRYPT_SM4_DATALEN_ERROR;
    }
    Vpsm4CbcEncrypt(in, out, len, ctx->rk, iv, 1);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM4_CBC_Decrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv)
{
    if (len < CRYPT_SM4_BLOCKSIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM4_DATALEN_ERROR);
        return CRYPT_SM4_DATALEN_ERROR;
    }
    Vpsm4CbcEncrypt(in, out, len, ctx->rk, iv, 0);
    return CRYPT_SUCCESS;
}
#endif // HITLS_CRYPTO_CBC

int32_t CRYPT_SM4_CTR_Encrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv)
{
    Vpsm4Ctr32EncryptBlocks(in, out, len, ctx->rk, iv);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM4_CTR_Decrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv)
{
    Vpsm4Ctr32EncryptBlocks(in, out, len, ctx->rk, iv);
    return CRYPT_SUCCESS;
}

#endif // HITLS_CRYPTO_SM4
