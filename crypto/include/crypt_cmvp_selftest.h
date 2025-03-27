/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef CRYPT_CMVP_SELFTEST_H
#define CRYPT_CMVP_SELFTEST_H

#include <stdint.h>
#include <stdbool.h>
#include "crypt_algid.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * @ingroup crypt_cmvp_selftest
 * @brief   DRBG algorithm self-check. If the self-check fails, the module does not enter the error state.
 * The DRBG self-check overwrites the initialized random number.
 * After the self-check is complete, the module must be initialized again.
 *
 * @param id DRBG algorithm id
 *
 * @return  true The test is successful.
 *          false The test failed.
 */
bool CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_AlgId id);

/**
 * @ingroup crypt_cmvp_selftest
 * @brief   Hash algorithm self-check. If the self-check fails, the module does not enter the error state.
 * Currently, only SHA1/SHA224/SHA256/SHA384/SHA512 is supported.
 *
 * @param id hash algorithm id
 *
 * @return  true The test is successful.
 *          false The test failed.
 */
bool CRYPT_CMVP_SelftestMd(CRYPT_MD_AlgId id);

/**
 * @ingroup crypt_cmvp_selftest
 * @brief   RSA Algorithm self-check. If the self-check fails, the module does not enter the error state.
 *
 * @return  true The test is successful.
 *          false The test failed.
 */
bool CRYPT_CMVP_SelftestRsa(void);

/**
 * @ingroup crypt_cmvp_selftest
 * @brief   Symmetric algorithm self-check. If the self-check fails, the module does not enter the error state.
 *
 * @return  true The test is successful.
 *          false The test failed.
 */
bool CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AlgId id);

/**
 * @ingroup crypt_cmvp_selftest
 * @brief   CHACHA20-POLY1305 algorithm self-check. If the self-check fails, the module does not enter the error state.
 *
 * @return  true The test is successful.
 *          false The test failed.
 */
bool CRYPT_CMVP_SelftestChacha20poly1305(void);

/**
 * @ingroup crypt_cmvp_selftest
 * @brief   DH algorithm self-check. If the self-check fails, the module does not enter the error state.
 *
 * @return  true The test is successful.
 *          false The test failed.
 */
bool CRYPT_CMVP_SelftestDh(void);

/**
 * @ingroup crypt_cmvp_selftest
 * @brief   DSA algorithm self-check. If the self-check fails, the module does not enter the error state.
 *
 * @return  true The test is successful.
 *          false The test failed.
 */
bool CRYPT_CMVP_SelftestDsa(void);

/**
 * @ingroup crypt_cmvp_selftest
 * @brief   ED25519 algorithm self-check. If the self-check fails, the module does not enter the error state.
 *
 * @return  true The test is successful.
 *          false The test failed.
 */
bool CRYPT_CMVP_SelftestEd25519(void);

/**
 * @ingroup crypt_cmvp_selftest
 * @brief   HKDF algorithm self-check. If the self-check fails, the module does not enter the error state.
 *
 * @return  true The test is successful.
 *          false The test failed.
 */
bool CRYPT_CMVP_SelftestHkdf(void);

/**
 * @ingroup crypt_cmvp_selftest
 * @brief   MAC algorithm self-check. If the self-check fails, the module does not enter the error state.
 * Currently, only support HMAC/CMAC/GMAC
 *
 * @param id MAC algorithm id
 *
 * @return  true The test is successful.
 *          false The test failed.
 */
bool CRYPT_CMVP_SelftestMac(CRYPT_MAC_AlgId id);

/**
 * @ingroup crypt_cmvp_selftest
 * @brief   PBKDF2 algorithm self-check. If the self-check fails, the module does not enter the error state.
 *
 * @return  true The test is successful.
 *          false The test failed.
 */
bool CRYPT_CMVP_SelftestPbkdf2(CRYPT_MAC_AlgId id);

/**
 * @ingroup crypt_cmvp_selftest
 * @brief   SCRYPT algorithm self-check. If the self-check fails, the module does not enter the error state.
 *
 * @return  true The test is successful.
 *          false The test failed.
 */
bool CRYPT_CMVP_SelftestScrypt(void);

/**
 * @ingroup crypt_cmvp_selftest
 * @brief   TLS1.2 KDF algorithm self-check. If the self-check fails, the module does not enter the error state.
 *
 * @return  true The test is successful.
 *          false The test failed.
 */
bool CRYPT_CMVP_SelftestKdfTls12(void);

/**
 * @ingroup crypt_cmvp_selftest
 * @brief   X25519 algorithm self-check. If the self-check fails, the module does not enter the error state.
 *
 * @return  true The test is successful.
 *          false The test failed.
 */
bool CRYPT_CMVP_SelftestX25519(void);

/**
 * @ingroup crypt_cmvp_selftest
 * @brief   ECDSA algorithm self-check. If the self-check fails, the module does not enter the error state.
 *
 * @return  true The test is successful.
 *          false The test failed.
 */
bool CRYPT_CMVP_SelftestEcdsa(void);

/**
 * @ingroup crypt_cmvp_selftest
 * @brief   ECDH algorithm self-check. If the self-check fails, the module does not enter the error state.
 *
 * @return  true The test is successful.
 *          false The test failed.
 */
bool CRYPT_CMVP_SelftestEcdh(void);

/**
 * @ingroup crypt_cmvp_selftest
 * @brief   SM2 algorithm self-check. If the self-check fails, the module does not enter the error state.
 *
 * @return  true The test is successful.
 *          false The test failed.
 */
bool CRYPT_CMVP_SelftestSM2(void);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // CRYPT_CMVP_SELFTEST_H
