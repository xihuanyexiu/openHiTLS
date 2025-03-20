/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * @file crypt_sm4_armv7.c
 * Description: sm4 mode armv7 implementation
 * Author:
 * Create: 2023-9-25
 * Modification History
 * DATE        NAME             DESCRIPTION
 * --------------------------------------------------------------------------
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SM4

#include "crypt_sm4_armv7.h"
#include "crypt_sm4.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "crypt_errno.h"

int32_t CRYPT_SM4_SetEncryptKey(CRYPT_SM4_Ctx *ctx, const uint8_t *key, uint32_t len)
{
    if (ctx == NULL || key == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != CRYPT_SM4_BLOCKSIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM4_ERR_KEY_LEN);
        return CRYPT_SM4_ERR_KEY_LEN;
    }
    CRYPT_SM4_Key(ctx, key);

    return CRYPT_SUCCESS;
}

#if defined(HITLS_CRYPTO_CTR) || defined(HITLS_CRYPTO_GCM)
int32_t CRYPT_SM4_CTR_Encrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    SM4_CTR_Encrypt(in, out, len, ctx->rk, iv);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM4_CTR_Decrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    SM4_CTR_Encrypt(in, out, len, ctx->rk, iv);
    return CRYPT_SUCCESS;
}
#endif

#endif /* HITLS_CRYPTO_SM4 */
