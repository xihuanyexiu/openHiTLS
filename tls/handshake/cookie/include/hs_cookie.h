/**
 * @copyright   Copyright (c) Huawei Technologies Co., Ltd. 2022-2023. All rights reserved.
 * @brief       cookie calculation and verification
 */

#ifndef HS_COOKIE_H
#define HS_COOKIE_H

#include <stdint.h>
#include <stdbool.h>
#include "tls.h"
#include "hs_msg.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Calculate the cookie
 * The mackey is updated each time the number of times that Cookie_SECRET_LIFETIME is calculated.
 *
 * @param ctx [IN] Handshake context
 * @param clientHello [IN] Parsed clientHello structure
 * @param cookie [OUT] Calculated cookie
 * @param cookieLen [OUT] Calculated cookie length.
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval For other error codes, see hitls_error.h.
 */
int32_t HS_CalcCookie(TLS_Ctx *ctx, const ClientHelloMsg *clientHello, uint8_t *cookie, uint32_t *cookieLen);

/**
 * @brief Verify the cookie.
 * If the first cookie verification fails, the previous mackey is used for verification again.
 *
 * @param ctx [IN] Handshake context
 * @param clientHello [IN] Parsed clientHello structure
 * @param isCookieValid [OUT] Indicates whether the verification is successful.
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval For other error codes, see hitls_error.h.
 */
int32_t HS_CheckCookie(TLS_Ctx *ctx, const ClientHelloMsg *clientHello, bool *isCookieValid);

#ifdef __cplusplus
}
#endif /* end __cplusplus */
#endif /* end HS_COOKIE_H */
