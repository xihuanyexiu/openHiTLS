/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CCM

#include "crypt_errno.h"
#include "crypt_modes.h"
#include "ccm_core.h"
#include "crypt_modes_ccm.h"

int32_t CcmBlocks(MODES_CCM_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, bool enc)
{
    XorCryptData data;
    data.in = in;
    data.out = out;
    data.ctr = ctx->last;
    data.tag = ctx->tag;

    uint8_t countLen = (ctx->nonce[0] & 0x07) + 1;
    uint32_t dataLen = len;
    void (*xorBlock)(XorCryptData *data) = enc ? XorInEncryptBlock : XorInDecryptBlock;
    void (*xor)(XorCryptData *data, uint32_t len) = enc ? XorInEncrypt : XorInDecrypt;
    while (dataLen >= CCM_BLOCKSIZE) { // process the integer multiple of 16bytes data
        (void)ctx->ciphMeth->encrypt(ctx->ciphCtx, ctx->nonce, ctx->last, CCM_BLOCKSIZE);
        xorBlock(&data);
        (void)ctx->ciphMeth->encrypt(ctx->ciphCtx, ctx->tag, ctx->tag, CCM_BLOCKSIZE);
        MODE_IncCounter(ctx->nonce + CCM_BLOCKSIZE - countLen, countLen); // counter +1
        dataLen -= CCM_BLOCKSIZE;
        data.in += CCM_BLOCKSIZE;
        data.out += CCM_BLOCKSIZE;
    }
    if (dataLen > 0) { // process the integer multiple of 16bytes data
        (void)ctx->ciphMeth->encrypt(ctx->ciphCtx, ctx->nonce, ctx->last, CCM_BLOCKSIZE);
        xor(&data, dataLen);
        MODE_IncCounter(ctx->nonce + CCM_BLOCKSIZE - countLen, countLen); // counter +1
    }
    return CRYPT_SUCCESS;
}
#endif