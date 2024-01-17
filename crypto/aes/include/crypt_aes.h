/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */
#ifndef CRYPT_AES_H
#define CRYPT_AES_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_AES

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define CRYPT_AES_MAX_ROUNDS  14
#define CRYPT_AES_MAX_KEYLEN  (4 * (CRYPT_AES_MAX_ROUNDS + 1))

/**
 * @ingroup CRYPT_AES_Key
 *
 * aes key structure
 */
typedef struct {
    uint32_t key[CRYPT_AES_MAX_KEYLEN];
    uint32_t rounds;
} CRYPT_AES_Key;

/**
 * @ingroup aes
 * @brief Set the AES encryption key.
 *
 * @param ctx [IN]  AES handle
 * @param key [IN]  Encryption key
 * @param len [IN]  Key length. The value must be 16 bytes.
*/
int32_t CRYPT_AES_SetEncryptKey128(CRYPT_AES_Key *ctx, const uint8_t *key, uint32_t len);

/**
 * @ingroup aes
 * @brief Set the AES encryption key.
 *
 * @param ctx [IN]  AES handle
 * @param key [IN]  Encryption key
 * @param len [IN]  Key length. The value must be 24 bytes.
*/
int32_t CRYPT_AES_SetEncryptKey192(CRYPT_AES_Key *ctx, const uint8_t *key, uint32_t len);

/**
 * @ingroup aes
 * @brief Set the AES encryption key.
 *
 * @param ctx [IN]  AES handle
 * @param key [IN]  Encryption key
 * @param len [IN]  Key length. The value must be 32 bytes.
*/
int32_t CRYPT_AES_SetEncryptKey256(CRYPT_AES_Key *ctx, const uint8_t *key, uint32_t len);

/**
 * @ingroup aes
 * @brief Set the AES decryption key.
 *
 * @param ctx [IN]  AES handle
 * @param key [IN] Decryption key
 * @param len [IN]  Key length. The value must be 16 bytes.
*/
int32_t CRYPT_AES_SetDecryptKey128(CRYPT_AES_Key *ctx, const uint8_t *key, uint32_t len);

/**
 * @ingroup aes
 * @brief Set the AES decryption key.
 *
 * @param ctx [IN]  AES handle
 * @param key [IN] Decryption key
 * @param len [IN]  Key length. The value must be 24 bytes.
*/
int32_t CRYPT_AES_SetDecryptKey192(CRYPT_AES_Key *ctx, const uint8_t *key, uint32_t len);

/**
 * @ingroup aes
 * @brief Set the AES decryption key.
 *
 * @param ctx [IN]  AES handle
 * @param key [IN] Decryption key
 * @param len [IN]  Key length. The value must be 32 bytes.
*/
int32_t CRYPT_AES_SetDecryptKey256(CRYPT_AES_Key *ctx, const uint8_t *key, uint32_t len);

/**
 * @ingroup aes
 * @brief AES encryption
 *
 * @param ctx [IN] AES handle, storing keys
 * @param in  [IN] Input plaintext data. The value must be 16 bytes.
 * @param out [OUT] Output ciphertext data. The length is 16 bytes.
 * @param len [IN] Block length.
*/
int32_t CRYPT_AES_Encrypt(const CRYPT_AES_Key *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

/**
 * @ingroup aes
 * @brief AES decryption
 *
 * @param ctx [IN] AES handle, storing keys
 * @param in  [IN] Input ciphertext data. The value must be 16 bytes.
 * @param out [OUT] Output plaintext data. The length is 16 bytes.
 * @param len [IN] Block length. The length is 16.
*/
int32_t CRYPT_AES_Decrypt(const CRYPT_AES_Key *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

/**
 * @ingroup aes
 * @brief Delete the AES key information.
 *
 * @param ctx [IN]  AES handle, storing keys
 * @return void
*/
void CRYPT_AES_Clean(CRYPT_AES_Key *ctx);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_AES

#endif // CRYPT_AES_H
