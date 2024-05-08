/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef BSL_BASE64_LOCAL_H
#define BSL_BASE64_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_BSL_BASE64
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BASE64_ERRNO_BASE ((uint32_t)101U << 16U)

/**
 * @ingroup bsl_base64
 * malloc failed
 */
#define BASE64_ERRNO_NOMEM (BASE64_ERRNO_BASE + 2U)

/**
 * @ingroup bsl_base64
 * invalid parameter
 */
#define BASE64_ERRNO_PARAM (BASE64_ERRNO_BASE + 3U)

/**
 * @ingroup bsl_base64
 * invalid PEM file
 */
#define BASE64_ERRNO_INVALPEMFORMAT (BASE64_ERRNO_BASE + 4U)

/**
 * @ingroup bsl_base64
 * buffer overflow
 */
#define BASE64_ERRNO_OVERFLOW (BASE64_ERRNO_BASE + 5U)

/**
 * @ingroup bsl_base64
 * invalid Base64 character
 */
#define BASE64_ERRNO_INVAL (BASE64_ERRNO_BASE + 40U)

#ifdef __cplusplus
}
#endif
#endif /* HITLS_BSL_BASE64 */
#endif
