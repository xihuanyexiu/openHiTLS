/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_BN

#include <stdint.h>
#include <stdbool.h>
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "bn_bincal.h"
#include "bn_asm.h"

int32_t MontSqrBin(BN_UINT *r, BN_Mont *mont, BN_Optimizer *opt, bool consttime)
{
    if (mont->mSize > 1) {
        MontMul_Asm(r, r, r, mont->mod, mont->k0, mont->mSize);
        return CRYPT_SUCCESS;
    }
    return MontSqrBinCore(r, mont, opt, consttime);
}

int32_t MontMulBin(BN_UINT *r, const BN_UINT *a, const BN_UINT *b, BN_Mont *mont,
    BN_Optimizer *opt, bool consttime)
{
    if (mont->mSize > 1) {
        MontMul_Asm(r, a, b, mont->mod, mont->k0, mont->mSize);
        return CRYPT_SUCCESS;
    }
    return MontMulBinCore(r, a, b, mont, opt, consttime);
}

int32_t MontEncBin(BN_UINT *r, BN_Mont *mont, BN_Optimizer *opt, bool consttime)
{
    if (mont->mSize > 1) {
        MontMul_Asm(r, r, mont->montRR, mont->mod, mont->k0, mont->mSize);
        return CRYPT_SUCCESS;
    }
    return MontEncBinCore(r, mont, opt, consttime);
}

void Reduce(BN_UINT *r, BN_UINT *x, const BN_UINT *m, uint32_t mSize, BN_UINT m0)
{
    if (mSize > 1) {
        BN_UINT *one = BSL_SAL_Malloc(sizeof(BN_UINT) * mSize);
        if (one == NULL) {
            ReduceCore(r, x, m, mSize, m0);  /* can't handle malloc failure, use ReduceCore */
            return;
        }
        (void)memset_s(one, sizeof(BN_UINT) * mSize, 0, sizeof(BN_UINT) * mSize);
        one[0] = 1;
        MontMul_Asm(r, x, one, m, m0, mSize);
        BSL_SAL_FREE(one);
        return;
    }
    ReduceCore(r, x, m, mSize, m0);
    return;
}
#endif /* HITLS_CRYPTO_BN */
