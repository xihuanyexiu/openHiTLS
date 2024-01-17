/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

/* BEGIN_HEADER */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "crypt_bn.h"
#include "bsl_sal.h"
#include "crypt_algid.h"
#include "crypt_types.h"
#include "eal_pkey_local.h"
#include "crypt_eal_pkey.h"
#include "crypt_errno.h"
#include "crypt_eal_rand.h"
#include "securec.h"
/* END_HEADER */

#define ERROR (-1)
#define ED448_KEY_LEN (57)
#define X448_KEY_LEN (56)
#define ED448_SIGN_LENGTH (114)
#define MSG_LEN (128)
#define MAX_CONTEXT_LEN (255)

void Set_Curve448_Pub(CRYPT_EAL_PkeyPub *ed448PubKey, int algId, uint8_t *keyData, uint32_t keyLen)
{
    ed448PubKey->id = algId;
    ed448PubKey->key.curve448Pub.data = keyData;
    ed448PubKey->key.curve448Pub.len = keyLen;
    return;
}

void Set_Curve448_Prv(CRYPT_EAL_PkeyPrv *ed448PrvKey, int algId, uint8_t *keyData, uint32_t keyLen)
{
    ed448PrvKey->id = algId;
    ed448PrvKey->key.curve448Prv.data = keyData;
    ed448PrvKey->key.curve448Prv.len = keyLen;
    return;
}

int ED448_Sign(const CRYPT_EAL_PkeyCtx *pkey, const uint8_t *data, uint32_t dataLen, uint8_t **sign, uint32_t *signLen)
{
    *sign = (uint8_t *)malloc(ED448_SIGN_LENGTH);
    ASSERT_TRUE(*sign != NULL);
    *signLen = ED448_SIGN_LENGTH;
    return CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHAKE256, data, dataLen, *sign, signLen);
exit:
    free(*sign);
    return ERROR;
}

/**
 * @test   SDV_CRYPTO_CURVE448_GET_PUB_API_TC001
 * @title  CRYPT_EAL_PkeyGetPrv test.
 * @precon nan
 * @brief
 *    1. Create the context of the curve448 algorithm, expected result 1.
 *    2. Call the CRYPT_EAL_PkeyGetPub method, where all parameters are valid, expected result 2.
 *    3. Call the CRYPT_EAL_PkeySetPub method to set private key, expected result 3.
 *    4. Call the CRYPT_EAL_PkeyGetPub method, where other parameters are valid, but:
 *       (1). ctx = NULL, expected result 4.
 *       (2). pub = NULL, expected result 4.
 *       (3). curve448Prv.data = NULL, expected result 4.
 *       (4). pub.id != pkey.id, expected result 5.
 *       (5). pub.len = 0 | *448_KEY_LEN - 1, expected result 6.
 *       (6). pub.len = *448_KEY_LEN + 1, expected result 7.
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_CURVE448_NO_PUBKEY
 *    3. CRYPT_SUCCESS
 *    4. CRYPT_NULL_INPUT
 *    5. CRYPT_EAL_ERR_ALGID
 *    6. CRYPT_CURVE448_KEYLEN_ERROR
 *    7. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CURVE448_GET_PUB_API_TC001(int curve448Id)
{
    int keyLen = curve448Id == CRYPT_PKEY_X448 ? X448_KEY_LEN : ED448_KEY_LEN;
    uint8_t pubKeyData[ED448_KEY_LEN] = {0};
    CRYPT_EAL_PkeyPub pub;
    Set_Curve448_Pub(&pub, curve448Id, pubKeyData, keyLen);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(curve448Id);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &pub), CRYPT_CURVE448_NO_PUBKEY);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &pub), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(NULL, &pub), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, NULL), CRYPT_NULL_INPUT);
    pub.key.curve448Pub.data = NULL;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &pub), CRYPT_NULL_INPUT);

    pub.key.curve448Pub.data = pubKeyData;
    pub.id = CRYPT_PKEY_DSA;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &pub), CRYPT_EAL_ERR_ALGID);

    pub.id = curve448Id;
    pub.key.curve448Pub.len = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &pub), CRYPT_CURVE448_KEYLEN_ERROR);

    pub.key.curve448Pub.data = pubKeyData;
    pub.key.curve448Pub.len = keyLen - 1;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &pub), CRYPT_CURVE448_KEYLEN_ERROR);

    pub.key.curve448Pub.data = pubKeyData;
    pub.key.curve448Pub.len = keyLen + 1;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &pub), CRYPT_SUCCESS);
exit:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_CURVE448_GET_PRV_API_TC001
 * @title  CRYPT_EAL_PkeyGetPrv test.
 * @precon nan
 * @brief
 *    1. Create the context of the curve448 algorithm, expected result 1.
 *    2. Call the CRYPT_EAL_PkeyGetPrv method, where all parameters are valid, expected result 2.
 *    3. Call the CRYPT_EAL_PkeySetPrv method to set private key, expected result 3.
 *    4. Call the CRYPT_EAL_PkeyGetPrv method, where other parameters are valid, but:
 *       (1). ctx = NULL, expected result 4.
 *       (2). prv = NULL, expected result 4.
 *       (3). curve448Prv.data = NULL, expected result 4.
 *       (4). prv.id != pkey.id, expected result 5.
 *       (5). prv.len = 0 | *448_KEY_LEN - 1, expected result 6.
 *       (6). prv.len = *448_KEY_LEN + 1, expected result 7.
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_CURVE448_NO_PRVKEY
 *    3. CRYPT_SUCCESS
 *    4. CRYPT_NULL_INPUT
 *    5. CRYPT_EAL_ERR_ALGID
 *    6. CRYPT_CURVE448_KEYLEN_ERROR
 *    7. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CURVE448_GET_PRV_API_TC001(int curve448Id)
{
    int keyLen = curve448Id == CRYPT_PKEY_X448 ? X448_KEY_LEN : ED448_KEY_LEN;
    uint8_t prvKeyData[ED448_KEY_LEN] = {0};
    CRYPT_EAL_PkeyPrv prv;
    Set_Curve448_Prv(&prv, curve448Id, prvKeyData, keyLen);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(curve448Id);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &prv), CRYPT_CURVE448_NO_PRVKEY);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &prv), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(NULL, &prv), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, NULL), CRYPT_NULL_INPUT);
    prv.key.curve448Prv.data = NULL;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &prv), CRYPT_NULL_INPUT);

    prv.key.curve448Prv.data = prvKeyData;
    prv.id = CRYPT_PKEY_DSA;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &prv), CRYPT_EAL_ERR_ALGID);

    prv.id = curve448Id;
    prv.key.curve448Prv.len = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &prv), CRYPT_CURVE448_KEYLEN_ERROR);

    prv.key.curve448Prv.len = keyLen - 1;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &prv), CRYPT_CURVE448_KEYLEN_ERROR);

    prv.key.curve448Prv.len = keyLen + 1;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &prv), CRYPT_SUCCESS);
exit:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_CURVE448_SET_PRV_API_TC001
 * @title  CRYPT_EAL_PkeySetPrv test.
 * @precon Valid public key and private key.
 * @brief
 *    1. Create the context of the ed448 algorithm, expected result 1.
 *    2. Call the CRYPT_EAL_PkeySetPrv method:
 *       (1). ctx = NULL, expected result 2.
 *       (2). prv = NULL, expected result 2.
 *       (3). prv.data = NULL, expected result 2.
 *       (5). prv.id != pkey.id, expected result 3.
 *       (6). prv.len = prvKey->len - 1 | prvKey->len + 1, expected result 4.
 *       (7). All parameters are valid, expected result 5.
 *    3. Call the CRYPT_EAL_PkeySetPub to set pub, expected result 5.
 *    4. Call the CRYPT_EAL_PkeyGetPrv to set prv, expected result 5.
 *    5. Compare the setted private key with the obtained private key, expected result 6.
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_NULL_INPUT
 *    3. CRYPT_EAL_ERR_ALGID
 *    4. CRYPT_CURVE448_KEYLEN_ERROR
 *    5. CRYPT_SUCCESS
 *    6. The two private keys are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CURVE448_SET_PRV_API_TC001(int curve448Id, Hex *pubKey, Hex *prvKey)
{
    uint8_t prvBuf[ED448_KEY_LEN] = {0};
    CRYPT_EAL_PkeyPrv setPrv, getPrv;
    CRYPT_EAL_PkeyPub setPub;

    Set_Curve448_Prv(&setPrv, curve448Id, prvKey->x, prvKey->len);
    Set_Curve448_Prv(&getPrv, curve448Id, prvBuf, prvKey->len);
    Set_Curve448_Pub(&setPub, curve448Id, pubKey->x, pubKey->len);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(curve448Id);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(NULL, &setPrv), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, NULL), CRYPT_NULL_INPUT);
    setPrv.key.curve448Prv.data = NULL;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &setPrv), CRYPT_NULL_INPUT);

    setPrv.key.curve448Prv.data = prvKey->x;
    setPrv.id = CRYPT_PKEY_DSA;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &setPrv), CRYPT_EAL_ERR_ALGID);

    setPrv.id = curve448Id;
    setPrv.key.curve448Prv.len = prvKey->len - 1;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &setPrv), CRYPT_CURVE448_KEYLEN_ERROR);
    setPrv.key.curve448Prv.len = prvKey->len + 1;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &setPrv), CRYPT_CURVE448_KEYLEN_ERROR);

    /* Public and private keys can coexist. When a public key is set, the original private key will not be deleted. */
    setPrv.key.curve448Prv.len = prvKey->len;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &setPrv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &setPub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &getPrv), CRYPT_SUCCESS);
    ASSERT_COMPARE("Compare PrvKey", getPrv.key.curve448Prv.data, getPrv.key.curve448Prv.len, prvKey->x, prvKey->len);

exit:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_CURVE448_SET_PUB_API_TC001
 * @title  CRYPT_EAL_PkeySetPub test.
 * @precon Valid public key and private key.
 * @brief
 *    1. Create the context of the ed448 algorithm, expected result 1.
 *    2. Call the CRYPT_EAL_PkeySetPub method:
 *       (1). ctx = NULL, expected result 2.
 *       (2). prv = NULL, expected result 2.
 *       (3). prv.data = NULL, expected result 2.
 *       (5). prv.id != pkey.id, expected result 3.
 *       (6). prv.len = prvKey->len - 1 | prvKey->len + 1, expected result 4.
 *       (7). All parameters are valid, expected result 5.
 *    3. Call the CRYPT_EAL_PkeySetPrv to set prv, expected result 5.
 *    4. Call the CRYPT_EAL_PkeyGetPub to set pub, expected result 5.
 *    5. Compare the setted public key with the obtained public key, expected result 6.
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_NULL_INPUT
 *    3. CRYPT_EAL_ERR_ALGID
 *    4. CRYPT_CURVE448_KEYLEN_ERROR
 *    5. CRYPT_SUCCESS
 *    6. The two public keys are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CURVE448_SET_PUB_API_TC001(int curve448Id, Hex *pubKey, Hex *prvKey)
{
    uint8_t pubBuf[ED448_KEY_LEN] = {0};
    CRYPT_EAL_PkeyPub setPub, getPub;
    CRYPT_EAL_PkeyPrv setPrv;

    Set_Curve448_Pub(&setPub, curve448Id, pubKey->x, pubKey->len);
    Set_Curve448_Pub(&getPub, curve448Id, pubBuf, pubKey->len);
    Set_Curve448_Prv(&setPrv, curve448Id, prvKey->x, prvKey->len);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(curve448Id);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(NULL, &setPub), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, NULL), CRYPT_NULL_INPUT);
    setPub.key.curve448Pub.data = NULL;
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &setPub), CRYPT_NULL_INPUT);

    setPub.key.curve448Pub.data = pubKey->x;
    setPub.id = CRYPT_PKEY_DSA;
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &setPub), CRYPT_EAL_ERR_ALGID);

    setPub.id = curve448Id;
    setPub.key.curve448Pub.len = pubKey->len - 1;
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &setPub), CRYPT_CURVE448_KEYLEN_ERROR);
    setPub.key.curve448Pub.len = pubKey->len + 1;
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &setPub), CRYPT_CURVE448_KEYLEN_ERROR);

    /* Public and private keys can coexist. When a private key is set, the original public key will not be deleted. */
    setPub.key.curve448Pub.len = pubKey->len;
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &setPub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &setPrv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &getPub), CRYPT_SUCCESS);
    ASSERT_COMPARE("Compare PubKey", getPub.key.curve448Pub.data, getPub.key.curve448Pub.len, pubKey->x, prvKey->len);

exit:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ED448_CTRL_API_TC001
 * @title  ED4438 CRYPT_EAL_PkeyCtrl test.
 * @precon Valid public key and private key.
 * @brief
 *    1. Create the context of the ed448 algorithm, expected result 1.
 *    2. Call the CRYPT_EAL_PkeyCtrl method, where other parameters are valid, but:
 *       (1). the option is not supported, expected result 2.
 *       (2). opt = CRYPT_CTRL_SET_ED448_PREHASH, expected result 3.
 *       (3). opt = CRYPT_CTRL_SET_ED448_CONTEXT, val = NULL, valLen = 0, expected result 4.
 *       (4). opt = CRYPT_CTRL_SET_ED448_CONTEXT, valLen > 255, expected result 5.
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_CURVE448_UNSUPPORTED_CTRL_OPTION
 *    3. CRYPT_SUCCESS
 *    4. CRYPT_NULL_INPUT
 *    5. CRYPT_CURVE448_CONTEXT_TOO_LONG
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ED448_CTRL_API_TC001(void)
{
    uint8_t context[255];

    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ED448);
    ASSERT_TRUE(ctx != NULL);

    uint32_t optValue = 1;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_ECC_USE_COFACTOR_MODE, &optValue, sizeof(uint32_t)),
        CRYPT_CURVE448_UNSUPPORTED_CTRL_OPTION);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_ED448_PREHASH, NULL, 0), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_ED448_CONTEXT, NULL, 1), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_ED448_CONTEXT, context, 256), CRYPT_CURVE448_CONTEXT_TOO_LONG);

exit:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ED448_SIGN_API_TC001
 * @title  ED448: CRYPT_EAL_PkeySign test.
 * @precon Prepare data for signature.
 * @brief
 *    1. Create the context of the ed448 algorithm, expected result 1.
 *    2. Call the CRYPT_EAL_PkeyCtrl method to set context and prehash, expected result 2.
 *    3. Call the CRYPT_EAL_PkeySign method, where all parameters are valid, expected result 3.
 *    4. Call the CRYPT_EAL_PkeySetPrv method to set private key, expected result 2.
 *    5. Call the CRYPT_EAL_PkeySign method, where other parameters are valid, but :
 *        (1) hashId != CRYPT_MD_SHAKE256, expected result 4
 *        (2) msg = NULL, expected result 5
 *        (3) signLen = NULL, expected result 5
 *        (4) sign = NULL, signLen != 0, expected result 5
 *        (5) sign = NULL, signLen = 0, expected result 5
 *        (6) signLen = 0 | ED448_SIGN_LENGTH -1, expected result 6
 *        (7) signLen = 64 | 65, expected result 7
 *    6. Call the CRYPT_EAL_PkeySign method, where other parameters are valid, expected result 7
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_CURVE448_NO_PRVKEY
 *    4. CRYPT_CURVE448_HASH_METH_ERROR
 *    5. CRYPT_NULL_INPUT
 *    6. CRYPT_CURVE448_SIGNLEN_ERROR
 *    7. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ED448_SIGN_API_TC001(int prehash, Hex *prvKey, Hex *msg)
{
    uint8_t sign[ED448_SIGN_LENGTH];
    uint32_t signLen = ED448_SIGN_LENGTH;
    int hashId = CRYPT_MD_SHAKE256;
    CRYPT_EAL_PkeyPrv prv;
    Set_Curve448_Prv(&prv, CRYPT_PKEY_ED448, prvKey->x, ED448_KEY_LEN);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ED448);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_ED448_CONTEXT, NULL, 0), CRYPT_SUCCESS);
    if (prehash == 1) {
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_ED448_PREHASH, NULL, 0), CRYPT_SUCCESS);
    }

    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, hashId, msg->x, msg->len, sign, &signLen), CRYPT_CURVE448_NO_PRVKEY);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &prv), CRYPT_SUCCESS);

    /* Incorrect hash algorithm ID. */
    ASSERT_EQ(
        CRYPT_EAL_PkeySign(ctx, CRYPT_MD_SHA256, msg->x, msg->len, sign, &signLen), CRYPT_CURVE448_HASH_METH_ERROR);

    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, hashId, NULL, msg->len, sign, &signLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, hashId, msg->x, msg->len, sign, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, hashId, msg->x, msg->len, NULL, &signLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, hashId, msg->x, msg->len, NULL, &signLen), CRYPT_NULL_INPUT);

    signLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, hashId, msg->x, msg->len, sign, &signLen), CRYPT_CURVE448_SIGNLEN_ERROR);
    signLen = ED448_SIGN_LENGTH - 1;
    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, hashId, msg->x, 0, sign, &signLen), CRYPT_CURVE448_SIGNLEN_ERROR);

    signLen = ED448_SIGN_LENGTH;
    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, hashId, msg->x, 0, sign, &signLen), CRYPT_SUCCESS);

exit:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ED448_SIGN_API_TC002
 * @title  ED448: CRYPT_EAL_PkeySign test.
 * @precon Prepare data for signature.
 * @brief
 *    1. Create the context of the ed448 algorithm, expected result 1.
 *    2. Call the CRYPT_EAL_PkeySetPrv method to set private key, expected result 2.
 *    3. Call the CRYPT_EAL_PkeySign method to compute the signature, expected result 3.
 *    4. Call the CRYPT_EAL_PkeyCtrl method to set context, expected result 2.
 *    5. Call the CRYPT_EAL_PkeySign method to compute the signature, expected result 2.
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_CURVE448_NO_CONTEXT
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ED448_SIGN_API_TC002(Hex *prvKey, Hex *msg)
{
    uint8_t sign[ED448_SIGN_LENGTH];
    uint32_t signLen = ED448_SIGN_LENGTH;
    int hashId = CRYPT_MD_SHAKE256;
    CRYPT_EAL_PkeyPrv ed448PrvKey;
    Set_Curve448_Prv(&ed448PrvKey, CRYPT_PKEY_ED448, prvKey->x, ED448_KEY_LEN);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *ed448Pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ED448);
    ASSERT_TRUE(ed448Pkey != NULL);

    /* Sign without context. */
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ed448Pkey, &ed448PrvKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySign(ed448Pkey, hashId, msg->x, msg->len, sign, &signLen), CRYPT_CURVE448_NO_CONTEXT);

    /* Set context. */
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ed448Pkey, CRYPT_CTRL_SET_ED448_CONTEXT, NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySign(ed448Pkey, hashId, msg->x, msg->len, sign, &signLen), CRYPT_SUCCESS);
exit:
    CRYPT_EAL_PkeyFreeCtx(ed448Pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ED448_VERIFY_API_TC001
 * @title  ED448: CRYPT_EAL_PkeySign test.
 * @precon Prepare data for signature.
 * @brief
 *    1. Create the context of the ed448 algorithm, expected result 1.
 *    2. Call the CRYPT_EAL_PkeyCtrl method to set prehash, expected result 2.
 *    3. Call the CRYPT_EAL_PkeyVerify method, where all parameters are valid, expected result 3.
 *    4. Call the CRYPT_EAL_PkeySetPub method to set public key, expected result 2.
 *    5. Call the CRYPT_EAL_PkeyVerify method, where all parameters are valid, expected result 4.
 *    6. Call the CRYPT_EAL_PkeyCtrl method to set context, expected result 2.
 *    7. Call the CRYPT_EAL_PkeyVerify method, where other parameters are valid, but :
 *        (1) hashId != CRYPT_MD_SHAKE256, expected result 5
 *        (2) msg = NULL, msgLen = 0, expected result 2
 *        (3) msg = NULL, expected result 6
 *        (4) sign = NULL, expected result 6
 *        (5) msgLen = 0, expected result 7
 *        (6) signLen != ED448_SIGN_LENGTH, expected result 8
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_CURVE448_NO_PUBKEY
 *    4. CRYPT_CURVE448_NO_CONTEXT
 *    5. CRYPT_CURVE448_HASH_METH_ERROR
 *    6. CRYPT_NULL_INPUT
 *    7. CRYPT_CURVE448_VERIFY_FAIL
 *    8. CRYPT_CURVE448_SIGNLEN_ERROR
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ED448_VERIFY_API_TC001(int prehash, Hex *pubKey, Hex *msg, Hex *sign)
{
    int hashId = CRYPT_MD_SHAKE256;
    CRYPT_EAL_PkeyPub pub;
    Set_Curve448_Pub(&pub, CRYPT_PKEY_ED448, pubKey->x, ED448_KEY_LEN);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ED448);
    ASSERT_TRUE(ctx != NULL);

    if (prehash == 1) {
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_ED448_PREHASH, NULL, 0), CRYPT_SUCCESS);
    }

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, hashId, msg->x, msg->len, sign->x, sign->len), CRYPT_CURVE448_NO_PUBKEY);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &pub), CRYPT_SUCCESS);

    /* Verify without context. */
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, hashId, msg->x, msg->len, sign->x, sign->len), CRYPT_CURVE448_NO_CONTEXT);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_ED448_CONTEXT, NULL, 0), CRYPT_SUCCESS);

    /* Invalid hash id */
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SHAKE128, msg->x, msg->len, sign->x, sign->len),
        CRYPT_CURVE448_HASH_METH_ERROR);

    ASSERT_NE(CRYPT_EAL_PkeyVerify(ctx, hashId, NULL, 0, sign->x, sign->len), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, hashId, NULL, msg->len, sign->x, sign->len), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, hashId, msg->x, msg->len, NULL, 0), CRYPT_NULL_INPUT);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, hashId, msg->x, 0, sign->x, sign->len), CRYPT_CURVE448_VERIFY_FAIL);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, hashId, msg->x, msg->len, sign->x, 0), CRYPT_CURVE448_SIGNLEN_ERROR);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, hashId, msg->x, msg->len, sign->x, (ED448_SIGN_LENGTH + 1)),
        CRYPT_CURVE448_SIGNLEN_ERROR);
exit:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ED448_VERIFY_API_TC002
 * @title  Whether the key context contains the public key affects the signature verification method.
 * @precon nan
 * @brief
 *    1. Create the context of the ed448 algorithm, expected result 1.
 *    2. Call the CRYPT_EAL_PkeyCtrl method to set prehash, expected result 2.
 *    3. Call the CRYPT_EAL_PkeyVerify method, expected result 3.
 *    4. Set private key and verify, expected result 3
 *    5. Set invalid public key and verify, expected result 4
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_CURVE448_NO_PUBKEY
 *    4. CRYPT_CURVE448_INVALID_PUBKEY
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ED448_VERIFY_API_TC002(int prehash, Hex *prvKey, Hex *pubKey, Hex *msg, Hex *sign)
{
    int hashId = CRYPT_MD_SHAKE256;
    CRYPT_EAL_PkeyPub ed448PubKey;
    CRYPT_EAL_PkeyPrv ed448PrvKey;

    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ED448);
    ASSERT_TRUE(ctx != NULL);

    /* Set prehash */
    if (prehash == 1) {
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_ED448_PREHASH, NULL, 0), CRYPT_SUCCESS);
    }

    /* Set context */
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_ED448_CONTEXT, NULL, 0), CRYPT_SUCCESS);

    /* Verify without public key */
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, hashId, msg->x, msg->len, sign->x, sign->len), CRYPT_CURVE448_NO_PUBKEY);

    /* Set private key */
    Set_Curve448_Prv(&ed448PrvKey, CRYPT_PKEY_ED448, prvKey->x, ED448_KEY_LEN);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &ed448PrvKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, hashId, msg->x, msg->len, sign->x, sign->len), CRYPT_CURVE448_NO_PUBKEY);

    /* Set invalid public key */
    Set_Curve448_Pub(&ed448PubKey, CRYPT_PKEY_ED448, pubKey->x, ED448_KEY_LEN);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &ed448PubKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, hashId, msg->x, msg->len, sign->x, sign->len), CRYPT_CURVE448_INVALID_PUBKEY);

exit:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ED448_VERIFY_API_TC003
 * @title  Whether the signature verification parameters match affects the signature verification method.
 * @precon nan
 * @brief
 *    1. Create two context(signCtx, verifyCtx) of the ed448 algorithm, expected result 1
 *    2. Set private key for signCtx, expected result 2
 *    3. Set prehash and context for signCtx, expected result 3
 *    4. Call the CRYPT_EAL_PkeySign method to compute signature, expected result 4
 *    5. Set public key for verifyCtx, expected result 5
 *    6. Set the same prehash and context for verifyCtx as signCtx, expected result 6
 *    7. Call the CRYPT_EAL_PkeyVerify method to verify the signature, expected result 7
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_SUCCESS
 *    4. CRYPT_SUCCESS
 *    5. CRYPT_SUCCESS
 *    6. CRYPT_SUCCESS
 *    7. CRYPT_CURVE448_VERIFY_FAIL
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ED448_VERIFY_API_TC003(int signPrehash, int verifyPrehash, Hex *signContext, Hex *verifyContext,
    Hex *prvKey, Hex *pubKey, Hex *msg, Hex *sign)
{
    uint8_t *outSign = NULL;
    uint32_t signLen;
    CRYPT_EAL_PkeyPub ed448PubKey;
    CRYPT_EAL_PkeyPrv ed448PrvKey;
    Set_Curve448_Prv(&ed448PrvKey, CRYPT_PKEY_ED448, prvKey->x, ED448_KEY_LEN);
    Set_Curve448_Pub(&ed448PubKey, CRYPT_PKEY_ED448, pubKey->x, ED448_KEY_LEN);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *signCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ED448);
    CRYPT_EAL_PkeyCtx *verifyCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ED448);
    ASSERT_TRUE(signCtx != NULL && verifyCtx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(signCtx, &ed448PrvKey), CRYPT_SUCCESS);

    if (signPrehash == 1) {
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(signCtx, CRYPT_CTRL_SET_ED448_PREHASH, NULL, 0), CRYPT_SUCCESS);
    }
    ASSERT_EQ(
        CRYPT_EAL_PkeyCtrl(signCtx, CRYPT_CTRL_SET_ED448_CONTEXT, signContext->x, signContext->len), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGetSignLen(signCtx), ED448_SIGN_LENGTH);

    ASSERT_EQ(ED448_Sign(signCtx, msg->x, msg->len, &outSign, &signLen), CRYPT_SUCCESS);
    ASSERT_EQ(signLen, ED448_SIGN_LENGTH);
    ASSERT_COMPARE("Compare Sign", sign->x, sign->len, outSign, signLen);

    if (verifyPrehash == 1) {
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(verifyCtx, CRYPT_CTRL_SET_ED448_PREHASH, NULL, 0), CRYPT_SUCCESS);
    }
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(verifyCtx, CRYPT_CTRL_SET_ED448_CONTEXT, verifyContext->x, verifyContext->len),
        CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(verifyCtx, &ed448PubKey), CRYPT_SUCCESS);

    /* During signature verification, the configurations of the prehash context are inconsistent. As a result, the
     * signature verification fails. */
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(verifyCtx, CRYPT_MD_SHAKE256, msg->x, msg->len, outSign, signLen),
        CRYPT_CURVE448_VERIFY_FAIL);

exit:
    CRYPT_EAL_PkeyFreeCtx(signCtx);
    CRYPT_EAL_PkeyFreeCtx(verifyCtx);
    free(outSign);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ED448_VERIFY_API_TC004
 * @title  Test the signature verification method when the msg does not match the signature.
 * @precon nan
 * @brief
 *    1. Create two contexts(signCtx, verifyCtx) of the ed448 algorithm, expected result 1
 *    2. Set context(NULL) for signCtx, expected result 2
 *    3. Set private key for signCtx, expected result 3
 *    4. Compute the signature(msgLen is 64), expected result 4
 *    5. Set public key for verifyCtx, expected result 5
 *    6. Verify the signature with correct msg, expected result 6
 *    7. Set context(NULL) for verifyCtx, expected result 7
 *    8. Verify the signature with correct msg, expected result 8
 *    9. Verify the signature with the first 32 bytes of the msg, expected result 9
 *    10. Verify the signature with correct msg and wrong sign(Truncate 57-byte signature), expected result 10
 *    11. Verify the signature with correct msg and wrong sign(114 bytes: all 0), expected result 11
 *    12. Verify the signature with wrong msg(64 bytes) and wrong sign(114 bytes: all 0 or all F), expected result 12
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_SUCCESS
 *    4. CRYPT_SUCCESS
 *    5. CRYPT_SUCCESS
 *    6. CRYPT_CURVE448_NO_CONTEXT
 *    7. CRYPT_SUCCESS
 *    8. CRYPT_SUCCESS
 *    9. CRYPT_CURVE448_VERIFY_FAIL
 *    10. CRYPT_CURVE448_SIGNLEN_ERROR
 *    11. CRYPT_CURVE448_VERIFY_FAIL
 *    12. CRYPT_CURVE448_VERIFY_FAIL
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ED448_VERIFY_API_TC004(Hex *prvKey, Hex *pubKey, Hex *msg, Hex *sign)
{
    uint8_t *outSign = NULL;
    uint32_t signLen;
    uint8_t invalidSign[ED448_SIGN_LENGTH] = {0};
    int hashId = CRYPT_MD_SHAKE256;
    CRYPT_EAL_PkeyPub prv;
    CRYPT_EAL_PkeyPrv pub;
    Set_Curve448_Prv(&pub, CRYPT_PKEY_ED448, prvKey->x, ED448_KEY_LEN);
    Set_Curve448_Pub(&prv, CRYPT_PKEY_ED448, pubKey->x, ED448_KEY_LEN);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *signCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ED448);
    CRYPT_EAL_PkeyCtx *verCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ED448);
    ASSERT_TRUE(signCtx != NULL && verCtx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(signCtx, CRYPT_CTRL_SET_ED448_CONTEXT, NULL, 0), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(signCtx, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(ED448_Sign(signCtx, msg->x, msg->len, &outSign, &signLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("Compare Sign", sign->x, sign->len, outSign, signLen);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(verCtx, &prv), CRYPT_SUCCESS);
    /* During signature verification, the context configuration is inconsistent. As a result, the signature verification
     * fails. */
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(verCtx, hashId, msg->x, msg->len, sign->x, sign->len), CRYPT_CURVE448_NO_CONTEXT);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(verCtx, CRYPT_CTRL_SET_ED448_CONTEXT, NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(verCtx, hashId, msg->x, msg->len, sign->x, sign->len), CRYPT_SUCCESS);

    /* wrong msg */
    ASSERT_EQ(
        CRYPT_EAL_PkeyVerify(verCtx, hashId, msg->x, msg->len - 32, sign->x, sign->len), CRYPT_CURVE448_VERIFY_FAIL);

    /* wrong sing len */
    ASSERT_EQ(
        CRYPT_EAL_PkeyVerify(verCtx, hashId, msg->x, msg->len, sign->x, sign->len - 57), CRYPT_CURVE448_SIGNLEN_ERROR);

    /* wrong sign(114 bytes: all 0) */
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(verCtx, hashId, msg->x, msg->len, invalidSign, signLen), CRYPT_CURVE448_VERIFY_FAIL);

    /* wrong msg(64 bytes: all F) and wrong sign(114 bytes: all 0) */
    memset_s(msg->x, msg->len, 0xff, msg->len);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(verCtx, hashId, msg->x, msg->len, invalidSign, signLen), CRYPT_CURVE448_VERIFY_FAIL);

    /* wrong msg(64 bytes: all F) and wrong sign(114 bytes: all F) */
    memset_s(invalidSign, ED448_SIGN_LENGTH, 0xff, ED448_SIGN_LENGTH);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(verCtx, hashId, msg->x, msg->len, invalidSign, signLen), CRYPT_CURVE448_VERIFY_FAIL);

exit:
    free(outSign);
    CRYPT_EAL_PkeyFreeCtx(signCtx);
    CRYPT_EAL_PkeyFreeCtx(verCtx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_CURVE448_DUP_CTX_FUNC_TC001
 * @title  CURVE448: CRYPT_EAL_PkeyDupCtx test.
 * @precon nan
 * @brief
 *    1. Create the context of the ed448 algorithm, expected result 1.
 *    2. Init the drbg, expected result 2.
 *    3. Generate a key pair, expected result 3.
 *    4. Call the CRYPT_EAL_PkeyDupCtx method to dup ed448 context, expected result 4.
 *    5. Call the CRYPT_EAL_PkeyGetKeyBits to get keyLen from contexts, expected result 5.
 *    6. Call the CRYPT_EAL_PkeyGetPub method to obtain the public key from the contexts, expected result 6.
 *    7. Compare public keys, expected result 7.
 * @expect
 *    1. Success, and context is not NULL.
 *    2-4. CRYPT_SUCCESS
 *    5. The key length obtained from both contexts is the same.
 *    6. CRYPT_SUCCESS
 *    7. The two public keys are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CURVE448_DUP_CTX_FUNC_TC001(int id)
{
    uint8_t *pubKey1 = NULL;
    uint8_t *pubKey2 = NULL;
    uint32_t keyLen1;
    uint32_t keyLen2;
    CRYPT_EAL_PkeyPub pub = {0};
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyCtx *dupCtx = NULL;

    TestMemInit();
    ctx = CRYPT_EAL_PkeyNewCtx(id);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);

    dupCtx = CRYPT_EAL_PkeyDupCtx(ctx);
    ASSERT_TRUE(dupCtx != NULL);
    ASSERT_EQ(dupCtx->references.count, 1);

    keyLen1 = CRYPT_EAL_PkeyGetKeyBits(ctx);
    keyLen2 = CRYPT_EAL_PkeyGetKeyBits(dupCtx);
    ASSERT_EQ(keyLen1, keyLen2);

    pubKey1 = calloc(1u, keyLen1);
    pubKey2 = calloc(1u, keyLen2);
    ASSERT_TRUE(pubKey1 != NULL && pubKey2 != NULL);

    Set_Curve448_Pub(&pub, id, pubKey1, keyLen1);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &pub), CRYPT_SUCCESS);
    Set_Curve448_Pub(&pub, id, pubKey2, keyLen2);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(dupCtx, &pub), CRYPT_SUCCESS);

    ASSERT_COMPARE("Compare dup key", pubKey1, keyLen1, pubKey2, keyLen2);

exit:
    CRYPT_EAL_RandDeinit();
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(dupCtx);
    BSL_SAL_Free(pubKey1);
    BSL_SAL_Free(pubKey2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ED448_SIGN_VERIFY_FUNC_TC001
 * @title  ED448: Set keys, sign, and verify.
 * @precon Test Vectors for Ed448:
 *         SECRET KEY, PUBLIC KEY, MESSAGE(different lengths), CONTEXT(different lengths), SIGNATURE
 * @brief
 *    1. Create two contexts(signCtx, verifyCtx) of the ED448 algorithm, expected result 1
 *    2. Set the context for signCtx and signCtx, expected result 2
 *    3. Set the prehash for signCtx and signCtx, expected result 2
 *    4. Set the private key for signCtx, expected result 2
 *    5. Set the public key for verifyCtx, expected result 2
 *    6. Call the CRYPT_EAL_PkeyGetSignLen method to get sign length, expected result 2
 *    7. Allocate the memory for the signature, expected result 2
 *    8. Compute the signature of ed448, expected result 2
 *    9. Compare Signatures, expected result 3.
 *    10. Verify the signature of ed448, expected result 2.
 * @expect
 *    1. Success, and context is not NULL.
 *    2. Success.
 *    3. The signature calculation result is the same as the signature vector.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ED448_SIGN_VERIFY_FUNC_TC001(Hex *prvKey, Hex *pubKey, Hex *msg, Hex *context, Hex *sign, int prehash)
{
#ifndef HITLS_CRYPTO_ED448
    SKIP_TEST();
#endif
    uint8_t *outSign = NULL;
    uint32_t signLen;
    CRYPT_EAL_PkeyPub ed448PubKey = {0};
    CRYPT_EAL_PkeyPrv ed448PrvKey = {0};

    Set_Curve448_Prv(&ed448PrvKey, CRYPT_PKEY_ED448, prvKey->x, prvKey->len);
    Set_Curve448_Pub(&ed448PubKey, CRYPT_PKEY_ED448, pubKey->x, pubKey->len);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *signCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ED448);
    CRYPT_EAL_PkeyCtx *verifyCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ED448);
    ASSERT_TRUE(signCtx != NULL && verifyCtx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(signCtx, CRYPT_CTRL_SET_ED448_CONTEXT, context->x, context->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(verifyCtx, CRYPT_CTRL_SET_ED448_CONTEXT, context->x, context->len), CRYPT_SUCCESS);
    if (prehash == 1) {
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(signCtx, CRYPT_CTRL_SET_ED448_PREHASH, NULL, 0), CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(verifyCtx, CRYPT_CTRL_SET_ED448_PREHASH, NULL, 0), CRYPT_SUCCESS);
    }

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(signCtx, &ed448PrvKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(verifyCtx, &ed448PubKey), CRYPT_SUCCESS);

    signLen = CRYPT_EAL_PkeyGetSignLen(signCtx);
    outSign = (uint8_t *)malloc(signLen);
    ASSERT_TRUE(outSign != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySign(signCtx, CRYPT_MD_SHAKE256, msg->x, msg->len, outSign, &signLen), CRYPT_SUCCESS);
    ASSERT_EQ(signLen, sign->len);
    ASSERT_EQ(memcmp(outSign, sign->x, signLen), 0);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(verifyCtx, CRYPT_MD_SHAKE256, msg->x, msg->len, outSign, signLen), CRYPT_SUCCESS);

exit:
    free(outSign);
    CRYPT_EAL_PkeyFreeCtx(signCtx);
    CRYPT_EAL_PkeyFreeCtx(verifyCtx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ED448_SIGN_VERIFY_FUNC_TC002
 * @title  ED448: generate a key pair, sign and verify.
 * @precon Test Vectors for Ed448: SECRET KEY, PUBLIC KEY, MESSAGE(different length), SIGNATURE
 * @brief
 *    1. Create the context(ctx) of the ed448 algorithm, expected result 1
 *    2. Init the drbg, expected result 2.
 *    3. Generate a key pair, expected result 2.
 *    4. Set the prehash for ctx, expected result 2
 *    5. Set the context for ctx, expected result 2
 *    6. Compute the signature of ed448, expected result 2
 *    7. Check the length of signature, expected result 3.
 *    8. Verify the signature of ed448, expected result 2.
 * @expect
 *    1. Success, and context is not NULL.
 *    2. Success.
 *    3. The signature length is 114.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ED448_SIGN_VERIFY_FUNC_TC002(int prehash, int contextLen, Hex *msg)
{
#ifndef HITLS_CRYPTO_ED448
    SKIP_TEST();
#endif
    uint8_t *sign = NULL;
    uint32_t signLen;
    uint8_t context[255];  // The context length is 255 bytes.

    TestMemInit();
    CRYPT_EAL_PkeyCtx *ed448Pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ED448);
    ASSERT_TRUE(ed448Pkey != NULL);

    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    /* Generate a key pair. */
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ed448Pkey), CRYPT_SUCCESS);

    if (prehash == 1) {
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ed448Pkey, CRYPT_CTRL_SET_ED448_PREHASH, NULL, 0), CRYPT_SUCCESS);
    }
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ed448Pkey, CRYPT_CTRL_SET_ED448_CONTEXT, context, contextLen), CRYPT_SUCCESS);

    ASSERT_EQ(ED448_Sign(ed448Pkey, msg->x, msg->len, &sign, &signLen), CRYPT_SUCCESS);
    ASSERT_EQ(signLen, ED448_SIGN_LENGTH);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ed448Pkey, CRYPT_MD_SHAKE256, msg->x, msg->len, sign, signLen), CRYPT_SUCCESS);

exit:
    CRYPT_EAL_RandDeinit();
    free(sign);
    CRYPT_EAL_PkeyFreeCtx(ed448Pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_X448_EXCH_API_TC001
 * @title  X448: CRYPT_EAL_PkeyComputeShareKey Test
 * @precon Test Vectors for X448: public key, private key
 * @brief
 *    1. Create two contexts(ctx, peerCtx) of the X448 algorithm, expected result 1.
 *    2. Call the CRYPT_EAL_PkeyComputeShareKey method, where:
 *       (1). share = NULL, other parameters are valid, expected result 2.
 *       (2). shareLen = NULL, other parameters are valid, expected result 2.
 *       (3). ctx->id != peerCtx->id, other parameters are valid, expected result 3.
 *       (4). shareLen != X448_KEY_LEN, other parameters are valid, expected result 4.
 *       (5). all parameters are valid, but the local ctx does not have a private key, expected result 5.
 *       (6). all parameters are valid, but the peer ctx does not have a public key, expected result 6.
 *       (7). all parameters are valid, but the public key of the peer ctx is invalid, expected result 7.
 * @expect
 *    1. Success, and two contexts are not NULL.
 *    2. CRYPT_NULL_INPUT
 *    3. CRYPT_EAL_ERR_ALGID
 *    4. CRYPT_CURVE448_KEYLEN_ERROR
 *    5. CRYPT_CURVE448_NO_PRVKEY
 *    6. CRYPT_CURVE448_NO_PUBKEY
 *    7. CRYPT_CURVE448_KEY_COMPUTE_FAILED.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_X448_EXCH_API_TC001(Hex *pubKey, Hex *prvKey)
{
    uint8_t pubKeyData[X448_KEY_LEN] = {0};  // Invalid Point
    uint8_t share[X448_KEY_LEN];
    uint32_t shareLen;
    CRYPT_EAL_PkeyPub pub;
    CRYPT_EAL_PkeyPrv prv;

    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_X448);
    CRYPT_EAL_PkeyCtx *peerCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_X448);
    ASSERT_TRUE(ctx != NULL && peerCtx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(ctx, peerCtx, NULL, &shareLen), CRYPT_NULL_INPUT);

    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(ctx, peerCtx, share, NULL), CRYPT_NULL_INPUT);

    /* The algorithm ID is incorrect. */
    peerCtx->id = CRYPT_PKEY_ED448;
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(ctx, peerCtx, share, &shareLen), CRYPT_EAL_ERR_ALGID);

    peerCtx->id = CRYPT_PKEY_X448;
    shareLen = X448_KEY_LEN - 1;
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(ctx, peerCtx, share, &shareLen), CRYPT_CURVE448_KEYLEN_ERROR);

    shareLen = X448_KEY_LEN;
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(ctx, peerCtx, share, &shareLen), CRYPT_CURVE448_NO_PRVKEY);

    /* Set the local private key. */
    Set_Curve448_Prv(&prv, CRYPT_PKEY_X448, prvKey->x, X448_KEY_LEN);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &prv), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(ctx, peerCtx, share, &shareLen), CRYPT_CURVE448_NO_PUBKEY);

    /* Set the peer public key. */
    Set_Curve448_Pub(&pub, CRYPT_PKEY_X448, pubKey->x, X448_KEY_LEN);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(peerCtx, &pub), CRYPT_SUCCESS);

    /* Setting the Peer Public Key (Invalid Point) */
    Set_Curve448_Pub(&pub, CRYPT_PKEY_X448, pubKeyData, X448_KEY_LEN);

    peerCtx->id = CRYPT_PKEY_X448;
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(peerCtx, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(ctx, peerCtx, share, &shareLen), CRYPT_CURVE448_KEY_COMPUTE_FAILED);

exit:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(peerCtx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_X448_EXCH_FUNC_TC001
 * @title  X448 key exchange test: set the key and exchange the key.
 * @precon Test Vectors for X448: One's public key, The other's private key, Their shared key
 * @brief
 *    1. Create two contexts(pkey1, pkey2) of the X448 algorithm, expected result 1.
 *    2. Set the public key and private key for pkey1 and pkey2, expected result 2.
 *    3. Compute the shared key from the privite value in pkey1 and the public vlaue in pkey2, expected result 2.
 *    4. Compare the shared key computed by step 5 and the share secret vector, expected result 3.
 * @expect
 *    1. Success, and two contexts are not NULL.
 *    2. Success.
 *    3. The two shared keys are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_X448_EXCH_FUNC_TC001(Hex *pubkey, Hex *prvkey, Hex *share)
{
#ifndef HITLS_CRYPTO_X448
    SKIP_TEST();
#endif
    uint8_t outShare[X448_KEY_LEN];
    uint32_t shareLen = X448_KEY_LEN;
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyCtx *peerCtx = NULL;

    CRYPT_EAL_PkeyPub pub = {0};
    CRYPT_EAL_PkeyPrv prv = {0};
    Set_Curve448_Prv(&prv, CRYPT_PKEY_X448, prvkey->x, prvkey->len);
    Set_Curve448_Pub(&pub, CRYPT_PKEY_X448, pubkey->x, pubkey->len);

    TestMemInit();
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_X448);
    peerCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_X448);
    ASSERT_TRUE(ctx != NULL && peerCtx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &prv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(peerCtx, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(peerCtx, &prv), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(ctx, peerCtx, outShare, &shareLen), CRYPT_SUCCESS);
    ASSERT_EQ(shareLen, share->len);
    ASSERT_EQ(memcmp(outShare, share->x, shareLen), 0);

exit:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(peerCtx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_X448_GEN_EXCH_FUNC_TC001
 * @title  X448 key exchange test: generate key pair and key exchange.
 * @precon nan
 * @brief
 *    1. Create two contexts(ctx1, ctx2) of the X448 algorithm, expected result 1.
 *    2. Init the drbg, expected result 2.
 *    3. Generate key pairs, expected result 2.
 *    4. Compute the shared key from the privite value in ctx1 and the public vlaue in ctx2, expected result 2.
 *    5. Compute the shared key from the privite value in ctx2 and the public vlaue in ctx1, expected result 2.
 *    6. Compare the shared keys computed in the preceding two steps, expected result 3.
 * @expect
 *    1. Success, and two contexts are not NULL.
 *    2. Success.
 *    3. The two shared keys are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_X448_GEN_EXCH_FUNC_TC001(void)
{
#ifndef HITLS_CRYPTO_X448
    SKIP_TEST();
#endif
    uint8_t share1[X448_KEY_LEN] = {0};
    uint8_t share2[X448_KEY_LEN] = {0};
    uint32_t share1Len = sizeof(share1);
    uint32_t share2Len = sizeof(share2);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx1 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_X448);
    CRYPT_EAL_PkeyCtx *ctx2 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_X448);
    ASSERT_TRUE(ctx1 != NULL && ctx2 != NULL);

    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx2), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(ctx1, ctx2, share1, &share1Len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(ctx2, ctx1, share2, &share2Len), CRYPT_SUCCESS);
    ASSERT_EQ(share1Len, share2Len);
    ASSERT_EQ(memcmp(share1, share2, share1Len), 0);

exit:
    CRYPT_EAL_RandDeinit();
    CRYPT_EAL_PkeyFreeCtx(ctx1);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_CURVE448_CMP_FUNC_TC001
 * @title  Curve448: The input and output parameters address are the same.
 * @precon Vector: private key and public key.
 * @brief
 *    1. Create the contexts(ctx1, ctx2) of the Curve448 algorithm, expected result 1
 *    2. Call the CRYPT_EAL_PkeyCmp to compare ctx1 and ctx2, expected result 2
 *    3. Set public key for ctx1, expected result 3
 *    4. Call the CRYPT_EAL_PkeyCmp to compare ctx1 and ctx2, expected result 4
 *    5. Set public key for ctx2, expected result 5
 *    6. Call the CRYPT_EAL_PkeyCmp to compare ctx1 and ctx2, expected result 6
 * @expect
 *    1. Success, and contexts are not NULL.
 *    2. CRYPT_ECC_KEY_PUBKEY_NOT_EQUAL
 *    3. CRYPT_SUCCESS
 *    4. CRYPT_ECC_KEY_PUBKEY_NOT_EQUAL
 *    5-6. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CURVE448_CMP_FUNC_TC001(int algId, Hex *pubKey)
{
    CRYPT_EAL_PkeyPub pub = {0};
    Set_Curve448_Pub(&pub, algId, pubKey->x, pubKey->len);

    TestMemInit();

    CRYPT_EAL_PkeyCtx *ctx1 = CRYPT_EAL_PkeyNewCtx(algId);
    CRYPT_EAL_PkeyCtx *ctx2 = CRYPT_EAL_PkeyNewCtx(algId);
    ASSERT_TRUE(ctx1 != NULL && ctx2 != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_CURVE448_NO_PUBKEY);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx1, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_CURVE448_NO_PUBKEY);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx2, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_SUCCESS);

exit:
    CRYPT_EAL_PkeyFreeCtx(ctx1);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ED448_KEY_PAIR_CHECK_FUNC_TC001
 * @title  Ed448: key pair check.
 * @precon Registering memory-related functions.
 * @brief
 *    1. Create two contexts(pubCtx, prvCtx) of the ed448 algorithm, expected result 1
 *    2. Set context and public key for pubCtx, expected result 2
 *    3. Set context and private key for prvCtx, expected result 3
 *    4. Check whether the public key matches the private key, expected result 4
 * @expect
 *    1. Success, and contexts are not NULL.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_SUCCESS
 *    4. Return CRYPT_SUCCESS when expect is 1, CRYPT_CURVE448_VERIFY_FAIL otherwise.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ED448_KEY_PAIR_CHECK_FUNC_TC001(Hex *pubkey, Hex *prvkey, Hex *context, int expect)
{
    CRYPT_EAL_PkeyCtx *pubCtx = NULL;
    CRYPT_EAL_PkeyCtx *prvCtx = NULL;
    CRYPT_EAL_PkeyPub pub = {0};
    CRYPT_EAL_PkeyPrv prv = {0};
    int expectRet = expect == 1 ? CRYPT_SUCCESS : CRYPT_CURVE448_VERIFY_FAIL;

    Set_Curve448_Prv(&prv, CRYPT_PKEY_ED448, prvkey->x, prvkey->len);
    Set_Curve448_Pub(&pub, CRYPT_PKEY_ED448, pubkey->x, pubkey->len);

    TestMemInit();
    pubCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ED448);
    prvCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ED448);
    ASSERT_TRUE(pubCtx != NULL && prvCtx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pubCtx, CRYPT_CTRL_SET_ED448_CONTEXT, context->x, context->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pubCtx, &pub), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(prvCtx, CRYPT_CTRL_SET_ED448_CONTEXT, context->x, context->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(prvCtx, &prv), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(pubCtx, prvCtx), expectRet);
exit:
    CRYPT_EAL_PkeyFreeCtx(pubCtx);
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_CURVE448_GET_KEY_LEN_FUNC_TC001
 * @title  Curve448: get public key length.
 * @brief
 *    1. Create a context of the Curve448 algorithm, expected result 1
 *    2. Get public key length, expected result 2
 * @expect
 *    1. Success, and context is not NULL.
 *    2. Equal to keyLen.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CURVE448_GET_KEY_LEN_FUNC_TC001(int id, int keyLen)
{
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtx(id);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_TRUE(CRYPT_EAL_PkeyGetKeyLen(pkey) == (uint32_t)keyLen);
exit:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_CURVE448_GET_KEY_BITS_FUNC_TC001
 * @title  Curve448: get key bits.
 * @brief
 *    1. Create a context of the Curve448 algorithm, expected result 1
 *    2. Get key bits, expected result 2
 * @expect
 *    1. Success, and context is not NULL.
 *    2. Equal to keyBits.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CURVE448_GET_KEY_BITS_FUNC_TC001(int id, int keyBits)
{
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtx(id);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_TRUE(CRYPT_EAL_PkeyGetKeyBits(pkey) == (uint32_t)keyBits);
exit:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_CURVE448_GET_SIGN_LEN_FUNC_TC001
 * @title  Curve448: get sign length.
 * @brief
 *    1. Create a context of the Curve448 algorithm, expected result 1
 *    2. Get sign length, expected result 2
 * @expect
 *    1. Success, and context is not NULL.
 *    2. Equal to signLen.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CURVE448_GET_SIGN_LEN_FUNC_TC001(int id, int signLen)
{
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtx(id);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_TRUE(CRYPT_EAL_PkeyGetSignLen(pkey) == (uint32_t)signLen);
exit:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */