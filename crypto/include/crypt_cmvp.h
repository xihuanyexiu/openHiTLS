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

#ifndef CRYPT_CMVP_H
#define CRYPT_CMVP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define CRYPT_CMVP_GM_SM2 (1)
#define CRYPT_CMVP_GM_SM3 (1 << 1)
#define CRYPT_CMVP_GM_SM4 (1 << 2)
#define CRYPT_CMVP_GM_DRBG (1 << 3)
#define CRYPT_CMVP_GM_MAC (1 << 4)
#define CRYPT_CMVP_GM_PBKDF (1 << 5)

/**
 * @ingroup crypt_cmvp
 *
 * CMVP Supported Modes
 */
typedef enum {
    CRYPT_CMVP_MODE_NONAPPROVED, /**< Non-approved mode. This mode is used by default after startup.*/
    CRYPT_CMVP_MODE_ISO19790,    /**< ISO19790 Approval model*/
    CRYPT_CMVP_MODE_FIPS,        /**< FIPS140-3 Approval model*/
    CRYPT_CMVP_MODE_NDCPP,       /**< NDCPP model */
    CRYPT_CMVP_MODE_GM,          /**< GM model */
    CRYPT_CMVP_MODE_MAX
} CRYPT_CMVP_MODE;

/**
 * @ingroup crypt_cmvp
 * @brief Switching mode. The switchover mode cannot be performed after the EAL interface is used.
 * Multi-thread is not supported.
 *
 * @param   mode [IN] Mode to switch
 *
 * @return Returned successfully: CRYPT_SUCCESS
 *         For other error codes, see crypt_errno.h
 */
int32_t CRYPT_CMVP_ModeSet(CRYPT_CMVP_MODE mode);

/**
 * @ingroup crypt_cmvp
 * @brief Obtains the current mode.
 *
 * @return Current mode
 */
CRYPT_CMVP_MODE CRYPT_CMVP_ModeGet(void);

/**
 * @ingroup crypt_cmvp
 * @brief Obtains whether the module is available.
 * Before using the EAL interface, call this interface to check whether the module is available.
 *
 * @return normal status:CRYPT_SUCCESS
 *         Error status: other values. For details, see crypt_errno.h
 */
int32_t CRYPT_CMVP_StatusGet(void);

/**
 * @ingroup crypt_cmvp
 * @brief Obtaining the Version Number
 *
 * @param None
 *
 * @return Version Number
 */
const char *CRYPT_CMVP_GetVersion(void);

/**
 * @ingroup crypt_cmvp
 * @brief CMVP Enable multithreading. To support multiple threads,
 * this interface must be called after BSL_SAL_RegThreadCallback is called.
 *
 * @param None
 *
 * @return Returned successfully:CRYPT_SUCCESS
 *         Error status: other values. For details, see crypt_errno.h
 */
int32_t CRYPT_CMVP_MultiThreadEnable(void);

/**
 * @ingroup crypt_cmvp
 * @brief   ShangMi algorithm self-check. If the self-check fails, the module does not enter the error state.
 *
 * @param None
 *
 * @return  0 The test is successful.
 *          non-zero number: Some algorithms self test failed.
 */
int32_t CRYPT_CMVP_SelftestGM(void);

/**
 * @ingroup crypt_cmvp
 * @brief CMVP Random bytes randomness test
 *
 * @param data [IN] random bytes to be tested.
 * @param len  [IN] length of bytes string.

 * @return Returned successfully:CRYPT_SUCCESS
 *         Error status: other values. For details, see crypt_errno.h
 */
int32_t CMVP_RandomnessTest(const uint8_t *data, const uint32_t len);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif // CRYPT_CMVP_H
