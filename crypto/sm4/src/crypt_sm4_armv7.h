/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * @file crypt_sm4_armv7.h
 * Description: sm4 mode armv7 header file
 * Author: gaoyu
 * Create: 2023-09-25
 */

#ifndef CRYPT_SM4_ARMV7_H
#define CRYPT_SM4_ARMV7_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SM4

#include <stdint.h>
#include "crypt_sm4.h"

void CRYPT_SM4_Key(CRYPT_SM4_Ctx *ctx, const uint8_t *key);

void SM4_CTR_Encrypt(const uint8_t *in, uint8_t *out, uint32_t blocks, const uint32_t *key, const uint8_t *iv);

#endif /* HITLS_CRYPTO_SM4 */
#endif