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

#include <stdint.h>
#include "bsl_params.h"
#include "provider_test_utils.h"

#define BSL_PARAM_MAX_NUMBER 1000
BSL_Param *TestFindParam(BSL_Param *param, int32_t key)
{
    if (key == 0) {
        return NULL;
    }
    if (param == NULL) {
        return NULL;
    }
    int32_t index = 0;
    while (param[index].key != 0 && index < BSL_PARAM_MAX_NUMBER) {
        if (param[index].key == key) {
            return &param[index];
        }
        index++;
    }
    return NULL;
}

const BSL_Param *TestFindConstParam(const BSL_Param *param, int32_t key)
{
    if (key == 0) {
        return NULL;
    }
    if (param == NULL) {
        return NULL;
    }
    int32_t index = 0;
    while (param[index].key != 0 && index < BSL_PARAM_MAX_NUMBER) {
        if (param[index].key == key) {
            return &param[index];
        }
        index++;
    }
    return NULL;
}
