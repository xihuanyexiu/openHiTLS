/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef CURVE448_LOCAL_H
#define CURVE448_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CURVE448

#include <stdint.h>
#include <stdbool.h>
#include "crypt_local_types.h"
#include "crypt_curve448.h"
#include "sal_atomic.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FP_LIMB_LEN 16
#define FP_LIMB_HALF_LEN 8
#define SCALAR_LIMB_LEN 14
#define FP_LIMB_BITS 28
#define MASK28 0x0fffffff
#define MASK16 0xffff

#define ED448_PREHASH_MSG_LEN 64

#define CURVE448_NOKEY 0
#define CURVE448_PRVKEY 0x1
#define CURVE448_PUBKEY 0x10

#define CURVE448_NO_SET_CTX 256

#define GOTO_END_IF_FAIL(CODE)       \
    do {                             \
        ret = (CODE);                \
        if (ret != CRYPT_SUCCESS) {  \
            BSL_ERR_PUSH_ERROR(ret); \
            goto end;                \
        }                            \
    } while (0)

struct CryptCurve448Ctx {
    uint8_t prvKey[ED448_KEY_LEN];
    uint8_t pubKey[ED448_KEY_LEN];
    uint8_t context[ED448_CONTEXT_MAX_LEN]; /* maximum length of context is 255 */
    uint32_t ctxLen; /* 0 - 255, 256 is not set */
    uint8_t keyType; /* specify the key type */
    const EAL_MdMethod *hashMethod;
    bool preHash;
    BSL_SAL_RefCount references;
};

typedef struct Fp16 {
    uint32_t data[FP_LIMB_LEN];
} Fp16;

typedef struct Scalar {
    uint32_t data[SCALAR_LIMB_LEN];
} Scalar;

// niels to standard: y = a + b, x = b - a, z = 1, t = x * y
typedef struct Curve448Point {
    Fp16 x, y, z, t;
} Curve448Point;

typedef struct PointNiels {
    Fp16 a, b, c;
} PointNiels;

// standard to pniels: a = y - x, b = x + y, c = 2 * t * D, z = 2 * z
// pniels to standard: x = (b-a) * z, y = (b+a) * z, t = (b+a) * (b-a), z = z * z
typedef struct PointPNiels {
    Fp16 a, b, c, z;
} PointPNiels;

typedef struct MulBaseTable {
    PointNiels table[80]; // table is 5 * 16 = 80
} MulBaseTable;

typedef struct WnafSlide {
    int32_t position;
    int32_t val;
} WnafSlide;

#define CURVE448_FP_OP(dst, src1, src2, op)   \
    do {                                             \
        (dst).data[0] = (src1).data[0] op (src2).data[0];           \
        (dst).data[1] = (src1).data[1] op (src2).data[1];           \
        (dst).data[2] = (src1).data[2] op (src2).data[2];           \
        (dst).data[3] = (src1).data[3] op (src2).data[3];           \
        (dst).data[4] = (src1).data[4] op (src2).data[4];           \
        (dst).data[5] = (src1).data[5] op (src2).data[5];           \
        (dst).data[6] = (src1).data[6] op (src2).data[6];           \
        (dst).data[7] = (src1).data[7] op (src2).data[7];           \
        (dst).data[8] = (src1).data[8] op (src2).data[8];           \
        (dst).data[9] = (src1).data[9] op (src2).data[9];           \
        (dst).data[10] = (src1).data[10] op (src2).data[10];        \
        (dst).data[11] = (src1).data[11] op (src2).data[11];        \
        (dst).data[12] = (src1).data[12] op (src2).data[12];        \
        (dst).data[13] = (src1).data[13] op (src2).data[13];        \
        (dst).data[14] = (src1).data[14] op (src2).data[14];        \
        (dst).data[15] = (src1).data[15] op (src2).data[15];        \
    } while (0)

#define CURVE448_FP_COPY(dst, src)   \
    do {                                             \
        (dst).data[0] = (src).data[0];           \
        (dst).data[1] = (src).data[1];           \
        (dst).data[2] = (src).data[2];           \
        (dst).data[3] = (src).data[3];           \
        (dst).data[4] = (src).data[4];           \
        (dst).data[5] = (src).data[5];           \
        (dst).data[6] = (src).data[6];           \
        (dst).data[7] = (src).data[7];           \
        (dst).data[8] = (src).data[8];           \
        (dst).data[9] = (src).data[9];           \
        (dst).data[10] = (src).data[10];        \
        (dst).data[11] = (src).data[11];        \
        (dst).data[12] = (src).data[12];        \
        (dst).data[13] = (src).data[13];        \
        (dst).data[14] = (src).data[14];        \
        (dst).data[15] = (src).data[15];        \
    } while (0)

#define CURVE448_FP_CSWAP(s, a, b)                                      \
    do {                                                                \
            uint32_t tLocal;                                            \
            const uint32_t ts = 0 - (s);                                \
            for (uint32_t ii = 0; ii < FP_LIMB_LEN; ii++) {             \
                tLocal = ts & (((a)[ii]) ^ ((b)[ii]));                  \
                (a)[ii] = ((a)[ii] ^ tLocal);                           \
                (b)[ii] = ((b)[ii] ^ tLocal);                           \
            }                                                           \
    } while (0)

/* Add */
#define CURVE448_FP_ADD(dst, src1, src2) CURVE448_FP_OP(dst, src1, src2, +)

void ProcessSubCarry(Fp16 *in);
/* Subtract */
#define CURVE448_FP_SUB(dst, src1, src2)    \
    do {                                    \
        CURVE448_FP_OP(dst, src1, src2, -); \
        ProcessSubCarry(&(dst));              \
    } while (0)

void Curve448PrecomputedMulBase(Curve448Point *out, const Scalar *in);

#ifdef HITLS_CRYPTO_ED448
void Ed448EncodePoint(uint8_t *out, const Curve448Point *in);
#endif

void ScalarDivideBy2(Scalar *out, const Scalar *in);

void ScalarDecode(Scalar *out, const uint8_t *in, uint32_t len);

void GenPubKeyTest(const uint8_t prvKey[ED448_KEY_LEN]);

void TableLookUp(PointNiels *out, uint32_t startRow, uint32_t index);

void ScalarAdd(Scalar *out, const Scalar *in1, const Scalar *in2);

void ScalarMontMul(Scalar *out, const Scalar *in1, const Scalar *in2);

void ScalarMul(Scalar *out, const Scalar *in1, const Scalar *in2);

void ScalarEncode(uint8_t *out, const Scalar *in);

#ifdef HITLS_CRYPTO_X448
void ScalarDecodeX448(Scalar *out, const uint8_t *in);

void X448EncodePoint(uint8_t *out, Curve448Point *in);

bool CRYPT_X448_ComputeSharedKeyValid(const uint8_t *prvKey, const uint8_t *pubKey, uint8_t *shareKey);
#endif

void Curve448FpInverse(Fp16 *out, Fp16 *in);

void Curve448EncodeFp(const Fp16 *in, uint8_t *out);

void Curve448DecodeFp(const uint8_t *in, Fp16 *out);

void Curve448FpMulNum(Fp16 *out, const Fp16 *in, uint32_t num);

void Curve448FpMul(Fp16 *out, const Fp16 *in1, const Fp16 *in2);

void Curve448FpSqr(Fp16 *out, const Fp16 *in);

int32_t ED448DecodePoint(Curve448Point *out, const uint8_t in[ED448_KEY_LEN]);

int32_t PointEqual(Curve448Point *a, Curve448Point *b);

const PointNiels *WnafTableLookUp(int32_t index);

void PointSetZero(Curve448Point *point);

int32_t Curve448KAMulPlusMulBase(Curve448Point *out, const Scalar *s, const Scalar *k, Curve448Point *a);

void ScalarNeg(Scalar *out);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_CURVE448

#endif // CURVE448_LOCAL_H
