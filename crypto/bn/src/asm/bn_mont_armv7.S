#include "hitls_build.h"
#ifdef HITLS_CRYPTO_BN

.file   "bn_mont_armv7.S"
.text
.arch   armv7-a
.fpu    neon

/*
 * Processing of each register during accumulation
 * curLo, curHi, preLo, preHiAlsoPassToNextLo, all are D registers.
 * ptrWrite points to the memory where data is written
 */
.macro  PROCESS_REG_ACC     curLo, curHi, preLo, preHiAlsoPassToNextLo, ptrWrite
    vadd.u64    \curLo, \curLo, \preHiAlsoPassToNextLo  // Lo(acc[cur]) += Hi(acc[pre])
    vst1.32     {\preLo[0]}, [\ptrWrite,:32]!           // The result of the previous time is written back to
                                                        // memory, and is placed here to reduce pipeline bubbles
    vshr.u64    \preHiAlsoPassToNextLo, \curLo, #16     // Lo(acc[cur]) is transferred to the next register Hi(acc[cur])
    vadd.u64    \curHi, \curHi, \preHiAlsoPassToNextLo
    vshr.u64    \preHiAlsoPassToNextLo, \curHi, #16     // Hi(acc[cur]) is transferred to the next processing,
                                                        // and preHiAlsoPassToNextLo is used for transferring
    vzip.16     \curLo, \curHi
.endm

/*
 * void MontMul_Armv7(BN_UINT *r, const BN_UINT *a, const BN_UINT *b, const BN_UINT *n, const BN_UINT k0, size_t size)
 */
.global MontMul_Armv7
.type   MontMul_Armv7, %function
.align  5
MontMul_Armv7:
    mov         r12, sp             // Record the initial SP. input parameters size and k0 are still in the stack
    stmdb       sp!, {r4-r11}       // Register stacking protection
    vstmdb      sp!, {d8-d15}       // Register stacking protection
    ldr         r5 , [r12, #4]      // r5 = size
    vld1.32     {d30[0]}, [r12]     // d30[0] = k0
    mov         r12, sp             // Record the sp

    sub         r7 , sp , #128
    veor        q6 , q6 , q6
    veor        q7 , q7 , q7
    sub         r7 , r7 , r5 , lsl#4    // Apply for a temporary space of 4 x size
    veor        q8 , q8 , q8
    veor        q9 , q9 , q9
    and         r7 , r7 , #-64          // The lower six bits are cleared, and the stack address is 64-bit aligned
    veor        q10, q10, q10
    veor        q11, q11, q11
    mov         sp , r7                 // Apply for space
    add         r7 , r7 , #256
    sub         r8 , r5 , #8
    veor        q12, q12, q12
    veor        q13, q13, q13

.LZeroize8x:
    subs        r8, r8, #8              // Loop increment, modify the flag bit,
                                        // And determine whether the calculated r8 is 0.
    vst1.64     {q6 - q7}, [r7,:256]!
    vst1.64     {q8 - q9}, [r7,:256]!
    vst1.64     {q10-q11}, [r7,:256]!
    vst1.64     {q12-q13}, [r7,:256]!
    bne         .LZeroize8x

    vld1.32     {d0-d3}, [r1]!          // a[0]~a[7]
    add         r6 , sp , #256          // r6 = r7
    add         r10, sp , #8            // Address for storing q[1] in the first round, which is calculated in advance
    mov         r9 , r5                 // r9 = size, backup
    b           .LMontMulOuter8x

.align  4
.LMontMulOuter8x:
    // Eight q are calculated in each round and stacked.
    // Accumulate the results of a[8*j]~a[8*j+7] * b[i] + q[i] * n[8*j]~n[8*j+7]
    // to the corresponding accumulator q6–q13.
    // The 128 bytes between sp and r7 are stored as b[0],q[0],b[1],q[1]......b[7],q[7],
    // each value occupies eight bytes.
    vld1.32     {d28[0]}, [r2]!         // b[i], i++
    veor        d8 , d8 , d8            // d8 = 0
    vzip.16     d28, d8                 // d28[1] = hi(b[i]), d28[0] = lo(b[i]), d8 = 0
    add         r7 , sp , #128
    vld1.32     {d4-d7}, [r3]!          // n[0]~n[7], r3 = &n[8]

    vmlal.u32   q6 , d28, d0[0]         // q6 = b[i] * a[0]
    vmlal.u32   q7 , d28, d0[1]         // q7 = b[i] * a[1]
    veor        d8 , d8 , d8            // d8 = 0
    vmlal.u32   q8 , d28, d1[0]         // q8 = b[i] * a[2]
    vshl.i64    d29, d13, #16           // d13 = q6[1] = hi(b[i]) * a[0]
    vmlal.u32   q9 , d28, d1[1]         // q9 = b[i] * a[3]
    vadd.u64    d29, d29, d12           // d12 = q6[0] = lo(b[i]) * a[0]
                                        // d29 = d13 << 16 + d12 = b[i] * a[0]
    vmlal.u32   q10, d28, d2[0]         // q10= b[i] * a[4]
    vmul.u32    d29, d29, d30           // d29 = b[i] * a[0] * k0 = q[0]
    vmlal.u32   q11, d28, d2[1]         // q11= b[i] * a[5]
    vst1.32     {d28}, [sp,:64]         // d28 = b[i] after split, pushed into a stack
    vmlal.u32   q12, d28, d3[0]         // q12= b[i] * a[6]
    vzip.16     d29, d8                 // d29 = q[0] after split
    vmlal.u32   q13, d28, d3[1]         // q13= b[i] * a[7]

    // 1
    vld1.32     {d28[0]}, [r2]!         // b[i], i++
    vmlal.u32   q6 , d29, d4[0]         // q6  += q[i] * n[0]
    veor        d10, d10, d10           // d10 = 0
    vmlal.u32   q7 , d29, d4[1]         // q7  += q[i] * n[1]
    vzip.16     d28, d10                // after split b[i]
    vmlal.u32   q8 , d29, d5[0]         // q8  += q[i] * n[2]
    vshr.u64    d12, d12, #16
    vmlal.u32   q9 , d29, d5[1]         // q9  += q[i] * n[3]
    vmlal.u32   q10, d29, d6[0]         // q10 += q[i] * n[4]
    vadd.u64    d12, d12, d13
    vmlal.u32   q11, d29, d6[1]         // q11 += q[i] * n[5]
    vshr.u64    d12, d12, #16
    vmlal.u32   q12, d29, d7[0]         // q12 += q[i] * n[6]
    vmlal.u32   q13, d29, d7[1]         // q13 += q[i] * n[7]
    vadd.u64    d14, d14, d12
    vst1.32     {d29}, [r10,:64]!       // d29 = q[i] after split , pushed into a stack

    vld1.64     {q6}, [r6,:128]!        // Get next Accumulator
    vmlal.u32   q7 , d28, d0[0]         // q7  = b[i] * a[0]
    veor        d8 , d8 , d8
    vmlal.u32   q8 , d28, d0[1]         // q8  = b[i] * a[1]
    vshl.i64    d29, d15, #16           // d15 = q7[1] = hi(b[i]) * a[0]
    vmlal.u32   q9 , d28, d1[0]         // q9  = b[i] * a[2]
    vadd.u64    d29, d29, d14
    vmlal.u32   q10, d28, d1[1]         // q10 = b[i] * a[3]
    vmul.u32    d29, d29, d30
    vmlal.u32   q11, d28, d2[0]         // q11 = b[i] * a[4]
    vst1.32     {d28}, [r10,:64]!       // d28 = b[i] after split, pushed into a stack
    vmlal.u32   q12, d28, d2[1]         // q12 = b[i] * a[5]
    vzip.16     d29, d8
    vmlal.u32   q13, d28, d3[0]         // q13 = b[i] * a[6]
    vmlal.u32   q6 , d28, d3[1]         // q6  = b[i] * a[7]


    // 2
    vld1.32     {d28[0]}, [r2]!         // b[i], i++
    vmlal.u32   q7 , d29, d4[0]         // q7  += q[i] * n[0]
    veor        d10, d10, d10           // d10 = 0
    vmlal.u32   q8 , d29, d4[1]         // q8  += q[i] * n[1]
    vzip.16     d28, d10                // b[i] after split
    vmlal.u32   q9 , d29, d5[0]         // q9  += q[i] * n[2]
    vshr.u64    d14, d14, #16
    vmlal.u32   q10, d29, d5[1]         // q10 += q[i] * n[3]
    vmlal.u32   q11, d29, d6[0]         // q11 += q[i] * n[4]
    vadd.u64    d14, d14, d15
    vmlal.u32   q12, d29, d6[1]         // q12 += q[i] * n[5]
    vshr.u64    d14, d14, #16
    vmlal.u32   q13, d29, d7[0]         // q13 += q[i] * n[6]
    vmlal.u32   q6 , d29, d7[1]         // q6  += q[i] * n[7]
    vadd.u64    d16, d16, d14
    vst1.32     {d29}, [r10,:64]!       // d29 = q[i] after split, pushed into a stack

    vld1.64     {q7}, [r6,:128]!        // Get next Accumulator
    vmlal.u32   q8 , d28, d0[0]         // q8  = b[i] * a[0]
    veor        d8 , d8 , d8
    vmlal.u32   q9 , d28, d0[1]         // q9  = b[i] * a[1]
    vshl.i64    d29, d17, #16           // d15 = q7[1] = hi(b[i]) * a[0]
    vmlal.u32   q10, d28, d1[0]         // q10 = b[i] * a[2]
    vadd.u64    d29, d29, d16
    vmlal.u32   q11, d28, d1[1]         // q11 = b[i] * a[3]
    vmul.u32    d29, d29, d30
    vmlal.u32   q12, d28, d2[0]         // q12 = b[i] * a[4]
    vst1.32     {d28}, [r10,:64]!       // d28 = b[i] after split, pushed into a stack
    vmlal.u32   q13, d28, d2[1]         // q13 = b[i] * a[5]
    vzip.16     d29, d8
    vmlal.u32   q6 , d28, d3[0]         // q6  = b[i] * a[6]
    vmlal.u32   q7 , d28, d3[1]         // q7  = b[i] * a[7]


    // 3
    vld1.32     {d28[0]}, [r2]!         // b[i], i++
    vmlal.u32   q8 , d29, d4[0]         // q8  += q[i] * n[0]
    veor        d10, d10, d10           // d10 = 0
    vmlal.u32   q9 , d29, d4[1]         // q9  += q[i] * n[1]
    vzip.16     d28, d10                // b[i] after split
    vmlal.u32   q10, d29, d5[0]         // q10 += q[i] * n[2]
    vshr.u64    d16, d16, #16
    vmlal.u32   q11, d29, d5[1]         // q11 += q[i] * n[3]
    vmlal.u32   q12, d29, d6[0]         // q12 += q[i] * n[4]
    vadd.u64    d16, d16, d17
    vmlal.u32   q13, d29, d6[1]         // q13 += q[i] * n[5]
    vshr.u64    d16, d16, #16
    vmlal.u32   q6 , d29, d7[0]         // q6  += q[i] * n[6]
    vmlal.u32   q7 , d29, d7[1]         // q7  += q[i] * n[7]
    vadd.u64    d18, d18, d16
    vst1.32     {d29}, [r10,:64]!       // d29 = q[i] after split, pushed into a stack

    vld1.64     {q8}, [r6,:128]!        // Get next Accumulator
    vmlal.u32   q9 , d28, d0[0]         // q9  = b[i] * a[0]
    veor        d8 , d8 , d8
    vmlal.u32   q10, d28, d0[1]         // q10 = b[i] * a[1]
    vshl.i64    d29, d19, #16           // d15 = q7[1] = hi(b[i]) * a[0]
    vmlal.u32   q11, d28, d1[0]         // q11 = b[i] * a[2]
    vadd.u64    d29, d29, d18
    vmlal.u32   q12, d28, d1[1]         // q12 = b[i] * a[3]
    vmul.u32    d29, d29, d30
    vmlal.u32   q13, d28, d2[0]         // q13 = b[i] * a[4]
    vst1.32     {d28}, [r10,:64]!       // d28 = b[i] after split, pushed into a stack
    vmlal.u32   q6 , d28, d2[1]         // q6  = b[i] * a[5]
    vzip.16     d29, d8
    vmlal.u32   q7 , d28, d3[0]         // q7  = b[i] * a[6]
    vmlal.u32   q8 , d28, d3[1]         // q8  = b[i] * a[7]


    // 4
    vld1.32     {d28[0]}, [r2]!         // b[i], i++
    vmlal.u32   q9 , d29, d4[0]         // q9  += q[i] * n[0]
    veor        d10, d10, d10           // d10 = 0
    vmlal.u32   q10, d29, d4[1]         // q10 += q[i] * n[1]
    vzip.16     d28, d10                // b[i] after split
    vmlal.u32   q11, d29, d5[0]         // q11 += q[i] * n[2]
    vshr.u64    d18, d18, #16
    vmlal.u32   q12, d29, d5[1]         // q12 += q[i] * n[3]
    vmlal.u32   q13, d29, d6[0]         // q13 += q[i] * n[4]
    vadd.u64    d18, d18, d19
    vmlal.u32   q6 , d29, d6[1]         // q6  += q[i] * n[5]
    vshr.u64    d18, d18, #16
    vmlal.u32   q7 , d29, d7[0]         // q7  += q[i] * n[6]
    vmlal.u32   q8 , d29, d7[1]         // q8  += q[i] * n[7]
    vadd.u64    d20, d20, d18
    vst1.32     {d29}, [r10,:64]!       // d29 = q[i] after split, pushed into a stack

    vld1.64     {q9}, [r6,:128]!        // Get next Accumulator
    vmlal.u32   q10, d28, d0[0]         // q10 = b[i] * a[0]
    veor        d8 , d8 , d8
    vmlal.u32   q11, d28, d0[1]         // q11 = b[i] * a[1]
    vshl.i64    d29, d21, #16           // d15 = q7[1] = hi(b[i]) * a[0]
    vmlal.u32   q12, d28, d1[0]         // q12 = b[i] * a[2]
    vadd.u64    d29, d29, d20
    vmlal.u32   q13, d28, d1[1]         // q13 = b[i] * a[3]
    vmul.u32    d29, d29, d30
    vmlal.u32   q6 , d28, d2[0]         // q6  = b[i] * a[4]
    vst1.32     {d28}, [r10,:64]!       // d28 = b[i] after split, pushed into a stack
    vmlal.u32   q7 , d28, d2[1]         // q7  = b[i] * a[5]
    vzip.16     d29, d8
    vmlal.u32   q8 , d28, d3[0]         // q8  = b[i] * a[6]
    vmlal.u32   q9 , d28, d3[1]         // q9  = b[i] * a[7]


    // 5
    vld1.32     {d28[0]}, [r2]!         // b[i], i++
    vmlal.u32   q10, d29, d4[0]         // q10 += q[i] * n[0]
    veor        d10, d10, d10           // d10 = 0
    vmlal.u32   q11, d29, d4[1]         // q11 += q[i] * n[1]
    vzip.16     d28, d10                // b[i] after split
    vmlal.u32   q12, d29, d5[0]         // q12 += q[i] * n[2]
    vshr.u64    d20, d20, #16
    vmlal.u32   q13, d29, d5[1]         // q13 += q[i] * n[3]
    vmlal.u32   q6 , d29, d6[0]         // q6  += q[i] * n[4]
    vadd.u64    d20, d20, d21
    vmlal.u32   q7 , d29, d6[1]         // q7  += q[i] * n[5]
    vshr.u64    d20, d20, #16
    vmlal.u32   q8 , d29, d7[0]         // q8  += q[i] * n[6]
    vmlal.u32   q9 , d29, d7[1]         // q9  += q[i] * n[7]
    vadd.u64    d22, d22, d20
    vst1.32     {d29}, [r10,:64]!       // d29 = q[i] after split, pushed into a stack

    vld1.64     {q10}, [r6,:128]!       // Get next Accumulator
    vmlal.u32   q11, d28, d0[0]         // q11 = b[i] * a[0]
    veor        d8 , d8 , d8
    vmlal.u32   q12, d28, d0[1]         // q12 = b[i] * a[1]
    vshl.i64    d29, d23, #16           // d15 = q7[1] = hi(b[i]) * a[0]
    vmlal.u32   q13, d28, d1[0]         // q13 = b[i] * a[2]
    vadd.u64    d29, d29, d22
    vmlal.u32   q6 , d28, d1[1]         // q6  = b[i] * a[3]
    vmul.u32    d29, d29, d30
    vmlal.u32   q7 , d28, d2[0]         // q7  = b[i] * a[4]
    vst1.32     {d28}, [r10,:64]!       // d28 = b[i] after split, pushed into a stack
    vmlal.u32   q8 , d28, d2[1]         // q8  = b[i] * a[5]
    vzip.16     d29, d8
    vmlal.u32   q9 , d28, d3[0]         // q9  = b[i] * a[6]
    vmlal.u32   q10, d28, d3[1]         // q10 = b[i] * a[7]


    // 6
    vld1.32     {d28[0]}, [r2]!         // b[i], i++
    vmlal.u32   q11, d29, d4[0]         // q11 += q[i] * n[0]
    veor        d10, d10, d10           // d10 = 0
    vmlal.u32   q12, d29, d4[1]         // q12 += q[i] * n[1]
    vzip.16     d28, d10                // b[i] after split
    vmlal.u32   q13, d29, d5[0]         // q13 += q[i] * n[2]
    vshr.u64    d22, d22, #16
    vmlal.u32   q6 , d29, d5[1]         // q6  += q[i] * n[3]
    vmlal.u32   q7 , d29, d6[0]         // q7  += q[i] * n[4]
    vadd.u64    d22, d22, d23
    vmlal.u32   q8 , d29, d6[1]         // q8  += q[i] * n[5]
    vshr.u64    d22, d22, #16
    vmlal.u32   q9 , d29, d7[0]         // q9  += q[i] * n[6]
    vmlal.u32   q10, d29, d7[1]         // q10 += q[i] * n[7]
    vadd.u64    d24, d24, d22
    vst1.32     {d29}, [r10,:64]!       // d29 = q[i] after split, pushed into a stack

    vld1.64     {q11}, [r6,:128]!       // Get next Accumulator
    vmlal.u32   q12, d28, d0[0]         // q12 = b[i] * a[0]
    veor        d8 , d8 , d8
    vmlal.u32   q13, d28, d0[1]         // q13 = b[i] * a[1]
    vshl.i64    d29, d25, #16           // d15 = q7[1] = hi(b[i]) * a[0]
    vmlal.u32   q6 , d28, d1[0]         // q6  = b[i] * a[2]
    vadd.u64    d29, d29, d24
    vmlal.u32   q7 , d28, d1[1]         // q7  = b[i] * a[3]
    vmul.u32    d29, d29, d30
    vmlal.u32   q8 , d28, d2[0]         // q8  = b[i] * a[4]
    vst1.32     {d28}, [r10,:64]!       // d28 = b[i] after split, pushed into a stack
    vmlal.u32   q9 , d28, d2[1]         // q9  = b[i] * a[5]
    vzip.16     d29, d8
    vmlal.u32   q10, d28, d3[0]         // q10  = b[i] * a[6]
    vmlal.u32   q11, d28, d3[1]         // q11 = b[i] * a[7]


    // 7
    vld1.32     {d28[0]}, [r2]!         // b[i], i++
    vmlal.u32   q12, d29, d4[0]         // q12 += q[i] * n[0]
    veor        d10, d10, d10           // d10 = 0
    vmlal.u32   q13, d29, d4[1]         // q13 += q[i] * n[1]
    vzip.16     d28, d10                // b[i] after split
    vmlal.u32   q6 , d29, d5[0]         // q6  += q[i] * n[2]
    vshr.u64    d24, d24, #16
    vmlal.u32   q7 , d29, d5[1]         // q7  += q[i] * n[3]
    vmlal.u32   q8 , d29, d6[0]         // q8  += q[i] * n[4]
    vadd.u64    d24, d24, d25
    vmlal.u32   q9 , d29, d6[1]         // q9  += q[i] * n[5]
    vshr.u64    d24, d24, #16
    vmlal.u32   q10, d29, d7[0]         // q10 += q[i] * n[6]
    vmlal.u32   q11, d29, d7[1]         // q11 += q[i] * n[7]
    vadd.u64    d26, d26, d24
    vst1.32     {d29}, [r10,:64]!       // d29 = q[i] after split, pushed into a stack

    vld1.64     {q12}, [r6,:128]!       // Get next Accumulator
    vmlal.u32   q13, d28, d0[0]         // q13  = b[i] * a[0]
    veor        d8 , d8 , d8
    vmlal.u32   q6 , d28, d0[1]         // q6  = b[i] * a[1]
    vshl.i64    d29, d27, #16           // d15 = q7[1] = hi(b[i]) * a[0]
    vmlal.u32   q7 , d28, d1[0]         // q7  = b[i] * a[2]
    vadd.u64    d29, d29, d26
    vmlal.u32   q8 , d28, d1[1]         // q8  = b[i] * a[3]
    vmul.u32    d29, d29, d30
    vmlal.u32   q9 , d28, d2[0]         // q9  = b[i] * a[4]
    vst1.32     {d28}, [r10,:64]!       // d28 = b[i] after split, pushed into a stack
    vmlal.u32   q10, d28, d2[1]         // q10 = b[i] * a[5]
    vzip.16     d29, d8
    vmlal.u32   q11, d28, d3[0]         // q11 = b[i] * a[6]
    vmlal.u32   q12, d28, d3[1]         // q12 = b[i] * a[7]


    vld1.32     {d28}, [sp,:64]         // b[i], i++
    vmlal.u32   q13, d29, d4[0]         // q13 += q[i] * n[0], After accumulation, the lowest 32 bits are discarded by mod r
    vld1.32     {d0-d3}, [r1]!          // The next round of the internal loop a[8*j]~a[8*j+7]
    vmlal.u32   q6 , d29, d4[1]         // q6  += q[i] * n[1]
    vmlal.u32   q7 , d29, d5[0]         // q7  += q[i] * n[2]
    vshr.u64    d26, d26, #16
    vmlal.u32   q8 , d29, d5[1]         // q8  += q[i] * n[3]
    vmlal.u32   q9 , d29, d6[0]         // q9  += q[i] * n[4]
    vadd.u64    d26, d26, d27
    vmlal.u32   q10, d29, d6[1]         // q10 += q[i] * n[5]
    vshr.u64    d26, d26, #16
    vmlal.u32   q11, d29, d7[0]         // q11 += q[i] * n[6]
    vmlal.u32   q12, d29, d7[1]         // q12 += q[i] * n[7]
    vadd.u64    d12, d12, d26
    vst1.32     {d29}, [r10,:64]        // d29 = after split q[i], pushed into a stack

    // reduce init
    add         r10, sp , #8
    sub         r8 , r5 , #8            // r8 = size - 8, eight blocks are calculated each time.

    b           .LMontMulInner8x

.align  4
.LMontMulInner8x:
    subs        r8 , r8 , #8            // Loop increment
    vld1.32     {d4-d7}, [r3]!          // The next round of the internal loop n[8*j]~n[8*j+7]
    vld1.64     {q13}, [r6:128]         // Get next Accumulator
    vld1.32     {d29}, [r10,:64]!       // q[i] is popped out of the stack,
                                        // And q[i] is read in advance for the next round of accumulation q*n
    // To reduce pipeline bubbles, the read operation of d28 is ready for the external circulation.
    vmlal.u32   q6 , d28, d0[0]         // q6  += b[i] * a[8*j]
    vmlal.u32   q7 , d28, d0[1]         // q7  += b[i] * a[8*j+1]
    vmlal.u32   q8 , d28, d1[0]         // q8  += b[i] * a[8*j+2]
    vmlal.u32   q9 , d28, d1[1]         // q9  += b[i] * a[8*j+3]
    vmlal.u32   q10, d28, d2[0]         // q10 += b[i] * a[8*j+4]
    vmlal.u32   q11, d28, d2[1]         // q11 += b[i] * a[8*j+5]
    vmlal.u32   q12, d28, d3[0]         // q12 += b[i] * a[8*j+6]
    vmlal.u32   q13, d28, d3[1]         // q13 += b[i] * a[8*j+7]

    it          ne
    addne       r6 , r6 , #16           // Point to the next accumulator. Each accumulator is a q register.
                                        // 128 bits = 16 bytes. No further offset is required in the last round.


    // 1
    // To reduce pipeline bubbles, the read operation of d29 is complete when a*b is calculated.
    vld1.32     {d28}, [r10,:64]!       // b[i] pops the stack.
                                        // Read b[i] in advance for the next round of accumulation a*b.
    vmlal.u32   q6 , d29, d4[0]         // q6  += q[i] * n[0]
    vmlal.u32   q7 , d29, d4[1]         // q7  += q[i] * n[1]
    vmlal.u32   q8 , d29, d5[0]         // q8  += q[i] * n[2]
    vmlal.u32   q9 , d29, d5[1]         // q9  += q[i] * n[3]
    vmlal.u32   q10, d29, d6[0]         // q10 += q[i] * n[4]
    vmlal.u32   q11, d29, d6[1]         // q11 += q[i] * n[5]
    vmlal.u32   q12, d29, d7[0]         // q12 += q[i] * n[6]
    vmlal.u32   q13, d29, d7[1]         // q13 += q[i] * n[7]
    vst1.64     {q6}, [r7,:128]!        // Accumulation completes the stack, used for the next round of accumulation highest accumulator.

    vld1.64     {q6 }, [r6,:128]        // Take the highest accumulator of the current round.
    vld1.32     {d29}, [r10,:64]!       // q[i] pops out of the stack, and q[i] is read in advance for the next round of accumulation q*n.
    vmlal.u32   q7 , d28, d0[0]         // q7  += b[i] * a[8*j]
    vmlal.u32   q8 , d28, d0[1]         // q8  += b[i] * a[8*j+1]
    vmlal.u32   q9 , d28, d1[0]         // q9  += b[i] * a[8*j+2]
    vmlal.u32   q10, d28, d1[1]         // q10 += b[i] * a[8*j+3]
    vmlal.u32   q11, d28, d2[0]         // q11 += b[i] * a[8*j+4]
    vmlal.u32   q12, d28, d2[1]         // q12 += b[i] * a[8*j+5]
    vmlal.u32   q13, d28, d3[0]         // q13 += b[i] * a[8*j+6]
    vmlal.u32   q6 , d28, d3[1]         // q6  += b[i] * a[8*j+7]

    it          ne
    addne       r6 , r6 , #16           // Point to the next accumulator. Each accumulator is a q register.
                                        // 128 bits = 16 bytes. No further offset is required in the last round.


    // 2
    // To reduce pipeline bubbles, the read operation of d29 is complete when a*b is calculated.
    vld1.32     {d28}, [r10,:64]!       // b[i] pops the stack.
                                        // Read b[i] in advance for the next round of accumulation a*b.
    vmlal.u32   q7 , d29, d4[0]         // q7  += q[i] * n[0]
    vmlal.u32   q8 , d29, d4[1]         // q8  += q[i] * n[1]
    vmlal.u32   q9 , d29, d5[0]         // q9  += q[i] * n[2]
    vmlal.u32   q10, d29, d5[1]         // q10 += q[i] * n[3]
    vmlal.u32   q11, d29, d6[0]         // q11 += q[i] * n[4]
    vmlal.u32   q12, d29, d6[1]         // q12 += q[i] * n[5]
    vmlal.u32   q13, d29, d7[0]         // q13 += q[i] * n[6]
    vmlal.u32   q6 , d29, d7[1]         // q6  += q[i] * n[7]
    vst1.64     {q7}, [r7,:128]!        // Accumulation completes the stack, used for the next round of accumulation highest accumulator.

    vld1.64     {q7 }, [r6,:128]        // Take the highest accumulator of the current round.
    vld1.32     {d29}, [r10,:64]!       // q[i] pops out of the stack, and q[i] is read in advance for the next round of accumulation q*n.
    vmlal.u32   q8 , d28, d0[0]         // q8  += b[i] * a[8*j]
    vmlal.u32   q9 , d28, d0[1]         // q9  += b[i] * a[8*j+1]
    vmlal.u32   q10, d28, d1[0]         // q10 += b[i] * a[8*j+2]
    vmlal.u32   q11, d28, d1[1]         // q11 += b[i] * a[8*j+3]
    vmlal.u32   q12, d28, d2[0]         // q12 += b[i] * a[8*j+4]
    vmlal.u32   q13, d28, d2[1]         // q13 += b[i] * a[8*j+5]
    vmlal.u32   q6 , d28, d3[0]         // q6  += b[i] * a[8*j+6]
    vmlal.u32   q7 , d28, d3[1]         // q7  += b[i] * a[8*j+7]

    it          ne
    addne       r6 , r6 , #16           // Point to the next accumulator. Each accumulator is a q register.
                                        // 128 bits = 16 bytes. No further offset is required in the last round.


    // 3
    // To reduce pipeline bubbles, the read operation of d29 is complete when a*b is calculated.
    vld1.32     {d28}, [r10,:64]!       // b[i] pops the stack.
                                        // Read b[i] in advance for the next round of accumulation a*b.
    vmlal.u32   q8 , d29, d4[0]         // q8  += q[i] * n[0]
    vmlal.u32   q9 , d29, d4[1]         // q9  += q[i] * n[1]
    vmlal.u32   q10, d29, d5[0]         // q10 += q[i] * n[2]
    vmlal.u32   q11, d29, d5[1]         // q11 += q[i] * n[3]
    vmlal.u32   q12, d29, d6[0]         // q12 += q[i] * n[4]
    vmlal.u32   q13, d29, d6[1]         // q13 += q[i] * n[5]
    vmlal.u32   q6 , d29, d7[0]         // q6  += q[i] * n[6]
    vmlal.u32   q7 , d29, d7[1]         // q7  += q[i] * n[7]
    vst1.64     {q8}, [r7,:128]!        // Accumulation completes the stack,
                                        // Used for the next round of accumulation highest accumulator.

    vld1.64     {q8 }, [r6,:128]        // Take the highest accumulator of the current round
    vld1.32     {d29}, [r10,:64]!       // q[i] pops out of the stack,
                                        // And q[i] is read in advance for the next round of accumulation q*n.
    vmlal.u32   q9 , d28, d0[0]         // q9  += b[i] * a[8*j]
    vmlal.u32   q10, d28, d0[1]         // q10 += b[i] * a[8*j+1]
    vmlal.u32   q11, d28, d1[0]         // q11 += b[i] * a[8*j+2]
    vmlal.u32   q12, d28, d1[1]         // q12 += b[i] * a[8*j+3]
    vmlal.u32   q13, d28, d2[0]         // q13 += b[i] * a[8*j+4]
    vmlal.u32   q6 , d28, d2[1]         // q6  += b[i] * a[8*j+5]
    vmlal.u32   q7 , d28, d3[0]         // q7  += b[i] * a[8*j+6]
    vmlal.u32   q8 , d28, d3[1]         // q8  += b[i] * a[8*j+7]

    it          ne
    addne       r6 , r6 , #16           // Point to the next accumulator. Each accumulator is a q register.
                                        // 128 bits = 16 bytes. No further offset is required in the last round.


    // 4
    // To reduce pipeline bubbles, the read operation of d29 is complete when a*b is calculated.
    vld1.32     {d28}, [r10,:64]!       // b[i] pops the stack.
                                        // Read b[i] in advance for the next round of accumulation a*b.
    vmlal.u32   q9 , d29, d4[0]         // q9  += q[i] * n[0]
    vmlal.u32   q10, d29, d4[1]         // q10 += q[i] * n[1]
    vmlal.u32   q11, d29, d5[0]         // q11 += q[i] * n[2]
    vmlal.u32   q12, d29, d5[1]         // q12 += q[i] * n[3]
    vmlal.u32   q13, d29, d6[0]         // q13 += q[i] * n[4]
    vmlal.u32   q6 , d29, d6[1]         // q6  += q[i] * n[5]
    vmlal.u32   q7 , d29, d7[0]         // q7  += q[i] * n[6]
    vmlal.u32   q8 , d29, d7[1]         // q8  += q[i] * n[7]
    vst1.64     {q9}, [r7,:128]!        // Accumulation completes the stack, used for the next round of accumulation highest accumulator.

    vld1.64     {q9 }, [r6,:128]        // Take the highest accumulator of the current round
    vld1.32     {d29}, [r10,:64]!       // q[i] pops out of the stack, and q[i] is read in advance for the next round of accumulation q*n.
    vmlal.u32   q10, d28, d0[0]         // q10 += b[i] * a[8*j]
    vmlal.u32   q11, d28, d0[1]         // q11 += b[i] * a[8*j+1]
    vmlal.u32   q12, d28, d1[0]         // q12 += b[i] * a[8*j+2]
    vmlal.u32   q13, d28, d1[1]         // q13 += b[i] * a[8*j+3]
    vmlal.u32   q6 , d28, d2[0]         // q6  += b[i] * a[8*j+4]
    vmlal.u32   q7 , d28, d2[1]         // q7  += b[i] * a[8*j+5]
    vmlal.u32   q8 , d28, d3[0]         // q8  += b[i] * a[8*j+6]
    vmlal.u32   q9 , d28, d3[1]         // q9  += b[i] * a[8*j+7]

    it          ne
    addne       r6 , r6 , #16           // Point to the next accumulator. Each accumulator is a q register.
                                        // 128 bits = 16 bytes. No further offset is required in the last round.


    // 5
    // To reduce pipeline bubbles, the read operation of d29 is complete when a*b is calculated.
    vld1.32     {d28}, [r10,:64]!       // b[i] pops the stack.
                                        // Read b[i] in advance for the next round of accumulation a*b.
    vmlal.u32   q10, d29, d4[0]         // q10 += q[i] * n[0]
    vmlal.u32   q11, d29, d4[1]         // q11 += q[i] * n[1]
    vmlal.u32   q12, d29, d5[0]         // q12 += q[i] * n[2]
    vmlal.u32   q13, d29, d5[1]         // q13 += q[i] * n[3]
    vmlal.u32   q6 , d29, d6[0]         // q6  += q[i] * n[4]
    vmlal.u32   q7 , d29, d6[1]         // q7  += q[i] * n[5]
    vmlal.u32   q8 , d29, d7[0]         // q8  += q[i] * n[6]
    vmlal.u32   q9 , d29, d7[1]         // q9  += q[i] * n[7]
    vst1.64     {q10}, [r7,:128]!       // Accumulation completes the stack, used for the next round of accumulation highest accumulator.

    vld1.64     {q10}, [r6,:128]        // Take the highest accumulator of the current round
    vld1.32     {d29}, [r10,:64]!       // q[i] pops out of the stack, and q[i] is read in advance for the next round of accumulation q*n.
    vmlal.u32   q11, d28, d0[0]         // q11 += b[i] * a[8*j]
    vmlal.u32   q12, d28, d0[1]         // q12 += b[i] * a[8*j+1]
    vmlal.u32   q13, d28, d1[0]         // q13 += b[i] * a[8*j+2]
    vmlal.u32   q6 , d28, d1[1]         // q6  += b[i] * a[8*j+3]
    vmlal.u32   q7 , d28, d2[0]         // q7  += b[i] * a[8*j+4]
    vmlal.u32   q8 , d28, d2[1]         // q8  += b[i] * a[8*j+5]
    vmlal.u32   q9 , d28, d3[0]         // q9  += b[i] * a[8*j+6]
    vmlal.u32   q10, d28, d3[1]         // q10 += b[i] * a[8*j+7]

    it          ne
    addne       r6 , r6 , #16           // Point to the next accumulator. Each accumulator is a q register.
                                        // 128 bits = 16 bytes. No further offset is required in the last round.

    // 6
    // To reduce pipeline bubbles, the read operation of d29 is complete when a*b is calculated.
    vld1.32     {d28}, [r10,:64]!       // b[i] pops the stack.
                                        // Read b[i] in advance for the next round of accumulation a*b.
    vmlal.u32   q11, d29, d4[0]         // q11 += q[i] * n[0]
    vmlal.u32   q12, d29, d4[1]         // q12 += q[i] * n[1]
    vmlal.u32   q13, d29, d5[0]         // q13 += q[i] * n[2]
    vmlal.u32   q6 , d29, d5[1]         // q6  += q[i] * n[3]
    vmlal.u32   q7 , d29, d6[0]         // q7  += q[i] * n[4]
    vmlal.u32   q8 , d29, d6[1]         // q8  += q[i] * n[5]
    vmlal.u32   q9 , d29, d7[0]         // q9  += q[i] * n[6]
    vmlal.u32   q10, d29, d7[1]         // q10 += q[i] * n[7]
    vst1.64     {q11}, [r7,:128]!       // Accumulation completes the stack, used for the next round of accumulation highest accumulator.

    vld1.64     {q11}, [r6,:128]        // Take the highest accumulator of the current round
    vld1.32     {d29}, [r10,:64]!       // q[i] pops out of the stack, and q[i] is read in advance for the next round of accumulation q*n.
    vmlal.u32   q12, d28, d0[0]         // q12 += b[i] * a[8*j]
    vmlal.u32   q13, d28, d0[1]         // q13 += b[i] * a[8*j+1]
    vmlal.u32   q6 , d28, d1[0]         // q6  += b[i] * a[8*j+2]
    vmlal.u32   q7 , d28, d1[1]         // q7  += b[i] * a[8*j+3]
    vmlal.u32   q8 , d28, d2[0]         // q8  += b[i] * a[8*j+4]
    vmlal.u32   q9 , d28, d2[1]         // q9  += b[i] * a[8*j+5]
    vmlal.u32   q10, d28, d3[0]         // q10 += b[i] * a[8*j+6]
    vmlal.u32   q11, d28, d3[1]         // q11 += b[i] * a[8*j+7]

    it          ne
    addne       r6 , r6 , #16           // Point to the next accumulator. Each accumulator is a q register.
                                        // 128 bits = 16 bytes. No further offset is required in the last round.

    // 7
    // To reduce pipeline bubbles, the read operation of d29 is complete when a*b is calculated.
    vld1.32     {d28}, [r10,:64]!       // b[i] pops the stack.
                                        // Read b[i] in advance for the next round of accumulation a*b.
    vmlal.u32   q12, d29, d4[0]         // q12 += q[i] * n[0]
    vmlal.u32   q13, d29, d4[1]         // q13 += q[i] * n[1]
    vmlal.u32   q6 , d29, d5[0]         // q6  += q[i] * n[2]
    vmlal.u32   q7 , d29, d5[1]         // q7  += q[i] * n[3]
    vmlal.u32   q8 , d29, d6[0]         // q8  += q[i] * n[4]
    vmlal.u32   q9 , d29, d6[1]         // q9  += q[i] * n[5]
    vmlal.u32   q10, d29, d7[0]         // q10 += q[i] * n[6]
    vmlal.u32   q11, d29, d7[1]         // q11 += q[i] * n[7]
    vst1.64     {q12}, [r7,:128]!       // Accumulation completes the stack, used for the next round of accumulation highest accumulator.

    vld1.64     {q12}, [r6,:128]        // Take the highest accumulator of the current round.
    vld1.32     {d29}, [r10,:64]!       // q[i] pops out of the stack, and q[i] is read in advance for the next round of accumulation q*n.
    vmlal.u32   q13, d28, d0[0]         // q13 += b[i] * a[8*j]
    vmlal.u32   q6 , d28, d0[1]         // q6  += b[i] * a[8*j+1]
    vmlal.u32   q7 , d28, d1[0]         // q7  += b[i] * a[8*j+2]
    vmlal.u32   q8 , d28, d1[1]         // q8  += b[i] * a[8*j+3]
    vmlal.u32   q9 , d28, d2[0]         // q9  += b[i] * a[8*j+4]
    vmlal.u32   q10, d28, d2[1]         // q10 += b[i] * a[8*j+5]
    vmlal.u32   q11, d28, d3[0]         // q11 += b[i] * a[8*j+6]
    vmlal.u32   q12, d28, d3[1]         // q12 += b[i] * a[8*j+7]

    it          ne
    addne       r6 , r6 , #16           // Point to the next accumulator. Each accumulator is a q register.
                                        // 128 bits = 16 bytes. No further offset is required in the last round.


    // last
    it          eq
    subeq       r1 , r1 , r5 , lsl#2
    vld1.32     {d28}, [sp,:64]         // b[i] pops the stack.
                                        // Read b[i] in advance for the next round of accumulation a*b
    vmlal.u32   q13, d29, d4[0]         // q13 += q[i] * n[8*j]
    vmlal.u32   q6 , d29, d4[1]         // q6  += q[i] * n[8*j+1]
    vld1.32     {d0-d3}, [r1]!          // The next round of the internal loop a[8*j]~a[8*j+7]
    vmlal.u32   q7 , d29, d5[0]         // q7  += q[i] * n[8*j+2]
    vmlal.u32   q8 , d29, d5[1]         // q8  += q[i] * n[8*j+3]
    add         r10, sp , #8            // Return to the initial address, address pointed to when reduce init
    vmlal.u32   q9 , d29, d6[0]         // q9  += q[i] * n[8*j+4]
    vmlal.u32   q10, d29, d6[1]         // q10 += q[i] * n[8*j+5]
    vmlal.u32   q11, d29, d7[0]         // q11 += q[i] * n[8*j+6]
    vmlal.u32   q12, d29, d7[1]         // q12 += q[i] * n[8*j+7]
    vst1.64     {q13}, [r7,:128]!       // Accumulation completes the stack, used for the next round of accumulation highest accumulator.

    bne         .LMontMulInner8x        // Indicates the flag of the subs in the first line of the inner loop

    // end of the inner loop
    subs        r9 , r9 , #8            // Loop increment of the outer loop, that is. size -= 8

    add         r6 , sp , #128
    vst1.64     {q6 - q7}, [r7,:256]!
    vst1.64     {q8 - q9}, [r7,:256]!
    vst1.64     {q10-q11}, [r7,:256]!
    vst1.64     {q12}, [r7,:128]       // The lowest q13, the lowest accumulator of the last round, has been stacked.

    vld1.64     {q6 - q7}, [r6,:256]!   // Initialize the accumulator S of a new round of outer circulation.
    vld1.64     {q8 - q9}, [r6,:256]!
    vld1.64     {q10-q11}, [r6,:256]!
    vld1.64     {q12-q13}, [r6,:256]!

    itt         ne
    subne       r3 , r3 , r5 , lsl#2
    bne         .LMontMulOuter8x

    veor        q2 , q2 , q2            // Clears temporary data in the stack.
    veor        q3 , q3 , q3
    add         r7 , sp , #128
    mov         r8 , r5
    vshr.u64    d10, d12, #16           // d12 = q6[0], Lowest block of accumulator, lo(acc[0])
    vst1.64     {q2-q3}, [sp,:256]!     // Clear the temporary data in the stack.
    vadd.u64    d13, d13, d10           // acc[0] / r
    vst1.64     {q2-q3}, [sp,:256]!     // Clear the temporary data in the stack.
    vst1.64     {q2-q3}, [sp,:256]!     // Clear the temporary data in the stack.
    vshr.u64    d10, d13, #16           // After accumulation, the least significant 32 bits are discarded by mod r,
                                        // (hi(acc[0])+lo(acc[0])>>16)>>16 = hi(acc[0])
    vst1.64     {q2-q3}, [sp,:256]!     // Clear the temporary data in the stack.
    vzip.16     d12, d13                // d12 = lo(acc[0]), d13 = hi(acc[0]) + lo(acc[0])>>16

    b           .LMontMulTransAcc2th

.align  4
.LMontMulTransAcc:
    // 1
    vld1.64     {q6 - q7}, [r6,:256]!   // Read the acc[0] to acc[7] of the next round.
    vadd.u64    d12, d12, d10           // acc[0] += hi(acc[7]) Of the last round
    vshr.u64    d10, d12, #16           // d10 = lo(acc[0])>>16
    vld1.64     {q8 - q9}, [r6,:256]!
    vadd.u64    d13, d13, d10           // hi(acc[0])+lo(acc[0])>>16, 48bit + 32bit
    vld1.64     {q10-q11}, [r6,:256]!
    vld1.64     {q12-q13}, [r6,:256]!
    vshr.u64    d10, d13, #16           // d10 = hi(acc[0])
    vzip.16     d12, d13                // Restore acc[0]

.LMontMulTransAcc2th:
    // d10 is only used to save the high bit of each round of acc and transfer it to the next round of accumulation.
    // The first round has been calculated on the top, but is written back in the second round
    // To reduce pipeline bubbles.
    // 2
    PROCESS_REG_ACC     d14, d15, d12, d10, r7

    // 3
    PROCESS_REG_ACC     d16, d17, d14, d10, r7

    // 4
    PROCESS_REG_ACC     d18, d19, d16, d10, r7

    // 5
    PROCESS_REG_ACC     d20, d21, d18, d10, r7

    // 6
    PROCESS_REG_ACC     d22, d23, d20, d10, r7

    // 7
    PROCESS_REG_ACC     d24, d25, d22, d10, r7

    // 8
    PROCESS_REG_ACC     d26, d27, d24, d10, r7

    subs        r8 , r8 , #8
    vst1.32     {d26[0]}, [r7,:32]!     // d26 = lo(acc[7]), After the calculation, the data is written back
                                        // To the memory. The acc is 64-bit and needs to be split into 32-bit data.

    bne         .LMontMulTransAcc

    vst1.32     {d10[0]}, [r7,:32]      // hi(acc[7]) for the last set of accumulators
    sub         r3 , r3 , r5 , lsl#2
    subs        r1 , sp, #0             // r1=sp, By the way, clear the flag bit.
    add         r2 , sp , r5 , lsl#2    // Flag used to judge the end of the subtraction operation.
                                        // When r1=r2, the operation ends.

// Small loops are not address-aligned.
.LSubMod:
    ldmia       r3!, {r8-r11}           // r8-r11 = n[k]~n[4k-1]
    ldmia       r1!, {r4-r7}            // r4-r7  = S[k]~S[4k-1]
    sbcs        r8 , r4 , r8
    sbcs        r9 , r5 , r9
    sbcs        r10, r6 , r10
    sbcs        r11, r7 , r11
    teq         r1 , r2
    stmia       r0!, {r8-r11}           // The result of S-n is written to r, and the final result
                                        // is S-n or S according to the condition.
    bne         .LSubMod

    ldr         r10, [r1]               // Highest block of the accumulator.
    mov         r11, sp
    veor        q2 , q2 , q2            // Clear q2 to 0.
    sub         r11, r2 , r11           // Indicates the number of bytes corresponding to size.
    veor        q3 , q3 , q3            // Clear q3 to 0.
    mov         r1 , sp
    sub         r0 , r0 , r11           // r0 redirects to r.
    mov         r3 , r2                 // When r3 points to sp+size, the stack space has 3 x size to be cleared.
    sbcs        r10, r10, #0            // Determine whether S-n has borrowing, and select S-n or S.
                                        // as the result according to the CF flag.

.LCondCopy:
    ldmia       r1!, {r4-r7}            // r1 point to S
    ldmia       r0 , {r8-r11}           // r0 points to r, and S-n is stored in r.
    itttt       lo                      // If S-n has borrowing, the status of cond is lo.
    movlo       r8 , r4                 // Condition assignment. Select r4(S) when borrowing is available.
                                        // Otherwise, keep r8(S-n).
    movlo       r9 , r5
    movlo       r10, r6
    movlo       r11, r7
    vst1.64     {q2-q3}, [r3,:256]!     // Clear sensitive data in the stack space.
    vst1.64     {q2-q3}, [r3,:256]!
    stmia       r0!, {r8-r11}           // Result write back r.
    ldmia       r1!, {r4-r7}            // The length can be exactly divisible by 8.
                                        // Therefore, eight data blocks are copied cyclically.
    ldmia       r0 , {r8-r11}
    sub         r1 , r1 , #32           // After S[8*k]~S[8*k+7] is read, the pointer is offset.
                                        // After sub, it points to S[8*k] again. Later, it is cleared.
    itttt       lo
    movlo       r8 , r4
    movlo       r9 , r5
    movlo       r10, r6
    movlo       r11, r7
    vst1.64     {q2-q3}, [r1,:256]!     // Clear sensitive data of S.
    vst1.64     {q2-q3}, [r3,:256]!
    stmia       r0!, {r8-r11}           // The result is written back to r.

    teq         r1 , r2                 // Loop termination condition.
    bne         .LCondCopy

    mov         sp , r12                // Restore sp.
    vldmia      sp!, {d8-d15}           // Restore non-volatile register.
    ldmia       sp!, {r4-r11}           // Restore non-volatile register.
    bx          lr
.size   MontMul_Armv7,.-MontMul_Armv7

#endif
