/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef SAL_TIME_IMPL_H
#define SAL_TIME_IMPL_H

#include "hitls_build.h"
#ifdef HITLS_BSL_SAL_TIME

#include <stdint.h>
#include <stddef.h>
#include "bsl_sal.h"

#ifdef __cplusplus
extern "C" {
#endif

int64_t TIME_GetSysTime(void);

uint32_t TIME_SysTimeGet(BSL_TIME *sysTime);

uint32_t TIME_DateToStrConvert(const BSL_TIME *dateTime, char *timeStr, size_t len);

uint32_t TIME_UtcTimeToDateConvert(int64_t utcTime, BSL_TIME *sysTime);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_BSL_SAL_TIME */

#endif // SAL_TIME_IMPL_H
