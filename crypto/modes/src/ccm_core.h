/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef CCM_CORE_H
#define CCM_CORE_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CCM

#include "crypt_utils.h"
#include "crypt_modes.h"
#include "crypt_modes_ccm.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

void XorInDecrypt(XorCryptData *data, uint32_t len);
void XorInEncrypt(XorCryptData *data, uint32_t len);
void XorInEncryptBlock(XorCryptData *data);
void XorInDecryptBlock(XorCryptData *data);
int32_t CcmBlocks(MODES_CCM_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, bool enc);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_CCM

#endif // CCM_CORE_H
