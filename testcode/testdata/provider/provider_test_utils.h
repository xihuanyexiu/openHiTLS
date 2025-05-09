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

#ifndef __PROVIDER_TEST_UTILS_H__
#define __PROVIDER_TEST_UTILS_H__

#include <stdint.h>
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif

BSL_Param *TestFindParam(BSL_Param *param, int32_t key);
const BSL_Param *TestFindConstParam(const BSL_Param *param, int32_t key);

#ifdef __cplusplus
}
#endif

#endif

