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

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CMVP

#include <string.h>
#include "crypt_cmvp_selftest.h"
#include "cmvp_common.h"
#include "err.h"
#include "crypt_errno.h"
#include "crypt_eal_mac.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "bsl_sal.h"
#include "crypt_local_types.h"

#define MAC_TYPE_HMAC_CMAC 1
#define MAC_TYPE_GMAC 2

typedef struct {
    uint32_t id;
    const char *key;
    const char *msg;
    const char *mac;
    const char *iv;
    uint32_t type;
} CMVP_MAC_VECTOR;

static const CMVP_MAC_VECTOR MAC_VECTOR[] = {
    // CRYPT_MAC_HMAC_MD5
    // https://datatracker.ietf.org/doc/html/rfc2202
    {
        .id = CRYPT_MAC_HMAC_MD5,
        .key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        .msg = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
        .mac = "56be34521d144c88dbb8c733f0e8b3f6",
        .iv = NULL,
        .type = MAC_TYPE_HMAC_CMAC
    },
    // CRYPT_MAC_HMAC_SHA1
    // https://datatracker.ietf.org/doc/html/rfc2202
    {
        .id = CRYPT_MAC_HMAC_SHA1,
        .key = "0102030405060708090a0b0c0d0e0f10111213141516171819",
        .msg = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        .mac = "4c9007f4026250c6bc8414f9bf50c86c2d7235da",
        .iv = NULL,
        .type = MAC_TYPE_HMAC_CMAC
    },
    // CRYPT_MAC_HMAC_SHA224
    // https://datatracker.ietf.org/doc/html/rfc4231.html#page-4
    {
        .id = CRYPT_MAC_HMAC_SHA224,
        .key = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        .msg = "4869205468657265",
        .mac = "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22",
        .iv = NULL,
        .type = MAC_TYPE_HMAC_CMAC
    },
    // CRYPT_MAC_HMAC_SHA256
    // https://datatracker.ietf.org/doc/html/rfc4231.html#page-4
    {
        .id = CRYPT_MAC_HMAC_SHA256,
        .key = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        .msg = "4869205468657265",
        .mac = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        .iv = NULL,
        .type = MAC_TYPE_HMAC_CMAC
    },
    // CRYPT_MAC_HMAC_SHA384
    // https://datatracker.ietf.org/doc/html/rfc4231.html#page-4
    {
        .id = CRYPT_MAC_HMAC_SHA384,
        .key = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        .msg = "4869205468657265",
        .mac = "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
        .iv = NULL,
        .type = MAC_TYPE_HMAC_CMAC
    },
    // CRYPT_MAC_HMAC_SHA512
    // https://datatracker.ietf.org/doc/html/rfc4231.html#page-4
    {
        .id = CRYPT_MAC_HMAC_SHA512,
        .key = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        .msg = "4869205468657265",
        .mac = "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833"
            "b7d6b8a702038b274eaea3f4e4be9d914""eeb61f1702e696c203a126854",
        .iv = NULL,
        .type = MAC_TYPE_HMAC_CMAC
    },
    // CRYPT_MAC_HMAC_SM3
    {
        .id = CRYPT_MAC_HMAC_SM3,
        .key = "4a656665",
        .msg = "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
        .mac = "2e87f1d16862e6d964b50a5200bf2b10b764faa9680a296a2405f24bec39f882",
        .iv = NULL,
        .type = MAC_TYPE_HMAC_CMAC
    },
    {
        .id = CRYPT_MAC_MAX,
        .key = NULL,
        .msg = NULL,
        .mac = NULL,
        .iv = NULL,
        .type = 0
    }
};

static void FreeData(uint8_t *key, uint8_t *msg, uint8_t *mac, uint8_t *expectMac, uint8_t *iv)
{
    BSL_SAL_Free(key);
    BSL_SAL_Free(msg);
    BSL_SAL_Free(mac);
    BSL_SAL_Free(expectMac);
    BSL_SAL_Free(iv);
}

static bool GetData(const CMVP_MAC_VECTOR *macVec, CRYPT_Data *key, CRYPT_Data *msg,
    CRYPT_Data *expectMac, CRYPT_Data *iv)
{
    key->data = CMVP_StringsToBins(macVec->key, &(key->len));
    GOTO_EXIT_IF(key->data == NULL, CRYPT_CMVP_COMMON_ERR);
    msg->data = CMVP_StringsToBins(macVec->msg, &(msg->len));
    GOTO_EXIT_IF(msg->data == NULL, CRYPT_CMVP_COMMON_ERR);
    expectMac->data = CMVP_StringsToBins(macVec->mac, &(expectMac->len));
    GOTO_EXIT_IF(expectMac->data == NULL, CRYPT_CMVP_COMMON_ERR);
    if (macVec->iv != NULL) {
        iv->data = CMVP_StringsToBins(macVec->iv, &(iv->len));
        GOTO_EXIT_IF(iv->data == NULL, CRYPT_CMVP_COMMON_ERR);
    }
    return true;
EXIT:
    return false;
}

const CMVP_MAC_VECTOR *FindMacVectorById(CRYPT_MAC_AlgId id)
{
    uint32_t num = sizeof(MAC_VECTOR) / sizeof(MAC_VECTOR[0]);
    const CMVP_MAC_VECTOR *macVec = NULL;

    for (uint32_t i = 0; i < num; i++) {
        if (MAC_VECTOR[i].id == id) {
            macVec = &MAC_VECTOR[i];
            return macVec;
        }
    }

    return NULL;
}

bool CRYPT_CMVP_SelftestMac(CRYPT_MAC_AlgId id)
{
    bool ret = false;
    CRYPT_EAL_MacCtx *ctx = NULL;
    CRYPT_Data key = { NULL, 0 };
    CRYPT_Data msg = { NULL, 0 };
    CRYPT_Data iv = { NULL, 0 };
    uint8_t *mac = NULL;
    uint32_t macLen = 0;
    CRYPT_Data expectMac = { NULL, 0 };

    const CMVP_MAC_VECTOR *macVec = FindMacVectorById(id);
    // HMAC-MD5 is a non-approved algorithm and does not provide self-test.
    if (macVec == NULL || macVec->msg == NULL || macVec->id == CRYPT_MAC_HMAC_MD5) {
        return false;
    }

    GOTO_EXIT_IF(!GetData(macVec, &key, &msg, &expectMac, &iv), CRYPT_CMVP_ERR_ALGO_SELFTEST);
    ctx = CRYPT_EAL_MacNewCtx(id);
    GOTO_EXIT_IF(ctx == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    if (macVec->type == MAC_TYPE_GMAC) {
        macLen = expectMac.len;
    } else {
        macLen = CRYPT_EAL_GetMacLen(ctx);
    }
    mac = BSL_SAL_Malloc(macLen);
    GOTO_EXIT_IF(mac == NULL, CRYPT_MEM_ALLOC_FAIL);
    GOTO_EXIT_IF(CRYPT_EAL_MacInit(ctx, key.data, key.len) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    if (macVec->type == MAC_TYPE_GMAC) {
        GOTO_EXIT_IF(CRYPT_EAL_MacCtrl(ctx, CRYPT_CTRL_SET_IV, iv.data, iv.len) != CRYPT_SUCCESS,
            CRYPT_CMVP_ERR_ALGO_SELFTEST);
        GOTO_EXIT_IF(CRYPT_EAL_MacCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &macLen, sizeof(uint32_t)) != CRYPT_SUCCESS,
            CRYPT_CMVP_ERR_ALGO_SELFTEST);
    }
    GOTO_EXIT_IF(CRYPT_EAL_MacUpdate(ctx, msg.data, msg.len) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_EXIT_IF(CRYPT_EAL_MacFinal(ctx, mac, &macLen) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_EXIT_IF(memcmp(mac, expectMac.data, expectMac.len) != 0, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    ret = true;
EXIT:
    FreeData(key.data, msg.data, mac, expectMac.data, iv.data);
    CRYPT_EAL_MacDeinit(ctx);
    CRYPT_EAL_MacFreeCtx(ctx);
    return ret;
}

#endif
