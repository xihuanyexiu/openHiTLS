/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_DRBG_HMAC

#include <stdlib.h>
#include <securec.h>
#include "crypt_errno.h"
#include "crypt_local_types.h"
#include "crypt_utils.h"
#include "bsl_sal.h"
#include "crypt_types.h"
#include "bsl_err_internal.h"
#include "drbg_local.h"

#define DRBG_HMAC_MAX_MDLEN (64)

typedef enum {
    DRBG_HMAC_SHA1SIZE = 20,
    DRBG_HMAC_SHA224SIZE = 28,
    DRBG_HMAC_SHA256SIZE = 32,
    DRBG_HMAC_SHA384SIZE = 48,
    DRBG_HMAC_SHA512SIZE = 64,
} DRBG_HmacSize;

typedef struct {
    uint8_t k[DRBG_HMAC_MAX_MDLEN];
    uint8_t v[DRBG_HMAC_MAX_MDLEN];
    uint32_t blockLen;
    const EAL_MacMethod *hmacMeth;
    const EAL_MdMethod *mdMeth;
    void *hmacCtx;
} DRBG_HmacCtx;

static int32_t Hmac(DRBG_HmacCtx *ctx, uint8_t mark, const CRYPT_Data *in1,
                    const CRYPT_Data *in2, const CRYPT_Data *in3)
{
    int32_t ret;
    uint32_t ctxKLen = sizeof(ctx->k);
    uint32_t ctxVLen = sizeof(ctx->v);
    // K = HMAC (K, V || mark || provided_data). mark can be 0x00 or 0x01,
    // provided_data = in1 || in2 || in3, private_data can be NULL
    if ((ret = ctx->hmacMeth->init(ctx->hmacCtx, ctx->k, ctx->blockLen)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto OUT;
    }
    if ((ret = ctx->hmacMeth->update(ctx->hmacCtx, ctx->v, ctx->blockLen)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto OUT;
    }
    if ((ret = ctx->hmacMeth->update(ctx->hmacCtx, &mark, 1)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto OUT;
    }
    if (!CRYPT_IsDataNull(in1) && (ret = ctx->hmacMeth->update(ctx->hmacCtx, in1->data, in1->len)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto OUT;
    }
    if (!CRYPT_IsDataNull(in2) && (ret = ctx->hmacMeth->update(ctx->hmacCtx, in2->data, in2->len)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto OUT;
    }
    if (!CRYPT_IsDataNull(in3) && (ret = ctx->hmacMeth->update(ctx->hmacCtx, in3->data, in3->len)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto OUT;
    }
    if ((ret = ctx->hmacMeth->final(ctx->hmacCtx, ctx->k, &ctxKLen)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto OUT;
    }
    // V = HMAC (K, V).
    if ((ret = ctx->hmacMeth->init(ctx->hmacCtx, ctx->k, ctx->blockLen)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto OUT;
    }
    if ((ret = ctx->hmacMeth->update(ctx->hmacCtx, ctx->v, ctx->blockLen)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto OUT;
    }
    if ((ret = ctx->hmacMeth->final(ctx->hmacCtx, ctx->v, &ctxVLen)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto OUT;
    }
OUT :
    // clear hmacCtx
    ctx->hmacMeth->deinit(ctx->hmacCtx);
    return ret;
}

static int32_t DRBG_HmacUpdate(DRBG_Ctx *drbg, const CRYPT_Data *in1, const CRYPT_Data *in2, const CRYPT_Data *in3)
{
    DRBG_HmacCtx *ctx = (DRBG_HmacCtx *)drbg->ctx;
    int32_t ret;
    // K = HMAC (K, V || 0x00 || provided_data).  V = HMAC (K, V),  provided_data have 3 input
    ret = Hmac(ctx, 0x00, in1, in2, in3);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // If (provided_data = Null), then return K and V. It's not an error, it's algorithmic.
    if (CRYPT_IsDataNull(in1) && CRYPT_IsDataNull(in2) && CRYPT_IsDataNull(in3)) {
        return ret;
    }
    // K = HMAC (K, V || 0x01 || provided_data).  V = HMAC (K, V)
    ret = Hmac(ctx, 0x01, in1, in2, in3);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return ret;
}

int32_t DRBG_HmacInstantiate(DRBG_Ctx *drbg, const CRYPT_Data *entropyInput, const CRYPT_Data *nonce,
    const CRYPT_Data *perstr)
{
    DRBG_HmacCtx *ctx = (DRBG_HmacCtx *)drbg->ctx;
    int32_t ret;

    // Key = 0x00 00...00.
    (void)memset_s(ctx->k, sizeof(ctx->k), 0, ctx->blockLen);

    // V = 0x01 01...01.
    (void)memset_s(ctx->v, sizeof(ctx->v), 1, ctx->blockLen);

    // seed_material = entropy_input || nonce || personalization_string.
    // (Key, V) = HMAC_DRBG_Update (seed_material, Key, V).
    ret = DRBG_HmacUpdate(drbg, entropyInput, nonce, perstr);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    return ret;
}

int32_t DRBG_HmacReseed(DRBG_Ctx *drbg, const CRYPT_Data *entropyInput, const CRYPT_Data *adin)
{
    int32_t ret;
    // seed_material = entropy_input || additional_input.
    // (Key, V) = HMAC_DRBG_Update (seed_material, Key, V).
    ret = DRBG_HmacUpdate(drbg, entropyInput, adin, NULL);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    return ret;
}

int32_t DRBG_HmacGenerate(DRBG_Ctx *drbg, uint8_t *out, uint32_t outLen, const CRYPT_Data *adin)
{
    DRBG_HmacCtx *ctx = (DRBG_HmacCtx *)drbg->ctx;
    const EAL_MacMethod *hmacMeth = ctx->hmacMeth;
    const uint8_t *temp = ctx->v;
    uint32_t tmpLen = ctx->blockLen;
    uint32_t len = outLen;
    uint8_t *buf = out;
    int32_t ret;

    // If additional_input ≠ Null, then (Key, V) = HMAC_DRBG_Update (additional_input, Key, V).
    if (adin != NULL && adin->data != NULL && adin->len != 0) {
        if ((ret = DRBG_HmacUpdate(drbg, adin, NULL, NULL)) != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    /**
    While (len (temp) < requested_number_of_bits) do:
        V = HMAC (Key, V).
        temp = temp || V.
    */
    for (;;) {
        if ((ret = hmacMeth->init(ctx->hmacCtx, ctx->k, ctx->blockLen)) != CRYPT_SUCCESS ||
            (ret = hmacMeth->update(ctx->hmacCtx, temp, ctx->blockLen)) != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto OUT;
        }
        if (len > ctx->blockLen) {
            if ((ret = hmacMeth->final(ctx->hmacCtx, buf, &tmpLen)) != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                goto OUT;
            }
            temp = buf;
        } else {
            uint32_t ctxVLen = sizeof(ctx->v);
            if ((ret = hmacMeth->final(ctx->hmacCtx, ctx->v, &ctxVLen)) != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                goto OUT;
            }
            // Intercepts the len-length V-value as an output, and because of len <= blockLen,
            // length of V is always greater than blockLen. Therefore, this problem does not exist.
            (void)memcpy_s(buf, len, ctx->v, len);
            break;
        }

        buf += ctx->blockLen;
        len -= ctx->blockLen;
    }

    //  (Key, V) = HMAC_DRBG_Update (additional_input, Key, V).
    if ((ret = DRBG_HmacUpdate(drbg, adin, NULL, NULL)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto OUT;
    }
OUT:
    // clear hmacCtx
    hmacMeth->deinit(ctx->hmacCtx);
    return ret;
}

void DRBG_HmacUnInstantiate(DRBG_Ctx *drbg)
{
    DRBG_HmacCtx *ctx = (DRBG_HmacCtx*)drbg->ctx;
    ctx->hmacMeth->deinit(ctx->hmacCtx);
    BSL_SAL_CleanseData((void *)(ctx->k), sizeof(ctx->k));
    BSL_SAL_CleanseData((void *)(ctx->v), sizeof(ctx->v));
}

DRBG_Ctx *DRBG_HmacDup(DRBG_Ctx *drbg)
{
    DRBG_HmacCtx *ctx = NULL;

    if (drbg == NULL) {
        return NULL;
    }

    ctx = (DRBG_HmacCtx*)drbg->ctx;

    return DRBG_NewHmacCtx(ctx->hmacMeth, ctx->mdMeth, &(drbg->seedMeth), drbg->seedCtx);
}

void DRBG_HmacFree(DRBG_Ctx *drbg)
{
    if (drbg == NULL) {
        return;
    }

    DRBG_HmacUnInstantiate(drbg);
    DRBG_HmacCtx *ctx = (DRBG_HmacCtx*)drbg->ctx;
    ctx->hmacMeth->deinitCtx(ctx->hmacCtx);
    BSL_SAL_FREE(drbg);
    return;
}

static int32_t DRBG_NewHmacCtxBase(uint32_t hmacSize, DRBG_Ctx *drbg)
{
    switch (hmacSize) {
        case DRBG_HMAC_SHA1SIZE:
            drbg->strength = 128;   // nist 800-90a specified the length must be 128
            return CRYPT_SUCCESS;
        case DRBG_HMAC_SHA224SIZE:
            drbg->strength = 192;   // nist 800-90a specified the length must be 192
            return CRYPT_SUCCESS;
        case DRBG_HMAC_SHA256SIZE:
        case DRBG_HMAC_SHA384SIZE:
        case DRBG_HMAC_SHA512SIZE:
            drbg->strength = 256;   // nist 800-90a specified the length must be 256
            return CRYPT_SUCCESS;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_DRBG_ALG_NOT_SUPPORT);
            return CRYPT_DRBG_ALG_NOT_SUPPORT;
    }
}

DRBG_Ctx *DRBG_NewHmacCtx(const EAL_MacMethod *hmacMeth, const EAL_MdMethod *mdMeth,
    const CRYPT_RandSeedMethod *seedMeth, void *seedCtx)
{
    DRBG_Ctx *drbg = NULL;
    DRBG_HmacCtx *ctx = NULL;
    static DRBG_Method meth = {
        DRBG_HmacInstantiate,
        DRBG_HmacGenerate,
        DRBG_HmacReseed,
        DRBG_HmacUnInstantiate,
        DRBG_HmacDup,
        DRBG_HmacFree
    };

    if (hmacMeth == NULL || mdMeth == NULL || seedMeth == NULL) {
        return NULL;
    }

    drbg = (DRBG_Ctx*)BSL_SAL_Malloc(sizeof(DRBG_Ctx) + sizeof(DRBG_HmacCtx) + hmacMeth->ctxSize);
    if (drbg == NULL) {
        return NULL;
    }

    ctx = (DRBG_HmacCtx*)(drbg + 1);
    ctx->hmacMeth = hmacMeth;
    ctx->mdMeth = mdMeth;
    ctx->hmacCtx = (void*)(ctx + 1);

    if (hmacMeth->initCtx(ctx->hmacCtx, mdMeth) != CRYPT_SUCCESS) {
        BSL_SAL_FREE(drbg);
        return NULL;
    }

    ctx->blockLen = hmacMeth->getLen(ctx->hmacCtx);

    if (DRBG_NewHmacCtxBase(ctx->blockLen, drbg) != CRYPT_SUCCESS) {
        BSL_SAL_FREE(drbg);
        return NULL;
    }

    drbg->state = DRBG_STATE_UNINITIALISED;
    drbg->reseedInterval = DRBG_MAX_RESEED_INTERVAL;

    drbg->meth = &meth;
    drbg->ctx = ctx;
    drbg->seedMeth = *seedMeth;
    drbg->seedCtx = seedCtx;

    // shift rightwards by 3, converting from bit length to byte length
    drbg->entropyRange.min = drbg->strength >> 3;
    drbg->entropyRange.max = DRBG_MAX_LEN;

    drbg->nonceRange.min = drbg->entropyRange.min / DRBG_NONCE_FROM_ENTROPY;
    drbg->nonceRange.max = DRBG_MAX_LEN;

    drbg->maxPersLen = DRBG_MAX_LEN;
    drbg->maxAdinLen = DRBG_MAX_LEN;
    drbg->maxRequest = DRBG_MAX_REQUEST;

    return drbg;
}
#endif
