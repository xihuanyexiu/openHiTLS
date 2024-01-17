/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

.arch   armv8-a+crypto
.file   "bn_mont_armv8.S"
.text

.global MontMul_Asm
.type   MontMul_Asm, %function
.align  5
MontMul_Asm:
    tst     x5, #7
    b.eq    MontSqr8
    tst     x5, #3
    b.eq    MontMul4

    stp     x29, x30, [sp, #-64]!
    add     x29, sp, #0
    stp     x23, x24, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x19, x20, [sp, #48]

    ldr     x17 , [x2], #8           // x17 = &b[0]
    lsl     x5 , x5 , #3
    sub     x22, sp , x5            // The space size needs to be applied for.
    ldp     x15 , x16 , [x1], #16     // a[0], a[1]

    and     x22, x22, #-16          // The lower four bits of the address are cleared.
    ldp     x9, x10, [x3], #16     // n[0], n[1]

    mul     x14 , x15 , x17            // x14 = lo(a[0] * b[0])
    umulh   x15 , x15 , x17            // x15 = hi(a[0] * b[0])
    mul     x6, x16 , x17            // x6 = lo(a[1] * b[0])
    umulh   x7, x16 , x17            // x7 = hi(a[1] * b[0])

    sub     x21, x5 , #16

    mul     x11, x14 , x4            // t[0] * k0
    mov     sp , x22                // Apply for Space.

    umulh   x9, x9, x11           // hi(n[0] * t[0]*k0)
    mul     x12, x10, x11           // lo(n[1] * t[0]*k0)
    umulh   x13, x10, x11           // hi(n[1] * t[0]*k0)

    subs    xzr, x14 , #1            // CF = lo(a[0] * b[0]) - 1
    adc     x9, x9, xzr
    cbz     x21, .L1stReduceEnd

.L1stReduce:
    ldr     x16 , [x1], #8
    adds    x14 , x6, x15            // x14 = hi(a[0] * b[0]) + lo(a[1] * b[0])
    sub     x21, x21, #8            // j--
    adc     x15 , x7, xzr

    ldr     x10, [x3], #8
    adds    x8, x12, x9           // x8 = lo(n[1] * t[0]*k0) + hi(n[0] * t[0]*k0)
    mul     x6, x16 , x17            // a[j] * b[0]
    adc     x9, x13, xzr           // x9 = hi(n[1] * t[0]*k0) + CF
    umulh   x7, x16 , x17

    adds    x8, x8, x14            // x8 += hi(a[0] * b[0]) + lo(a[1] * b[0])
    mul     x12, x10, x11           // n[j] * t[0]*k0
    adc     x9, x9, xzr
    umulh   x13, x10, x11
    str     x8, [x22], #8          // t[j-1]
    cbnz    x21, .L1stReduce

.L1stReduceEnd:
    adds    x14 , x6, x15
    sub     x1 , x1 , x5
    adc     x15 , x7, xzr

    adds    x8, x12, x9
    sub     x3 , x3 , x5            // x3 = &n[0]
    adc     x9, x13, xzr

    adds    x8, x8, x14
    sub     x24, x5 , #8            // i = size-1
    adcs    x9, x9, x15

    adc     x23, xzr, xzr           // x23 = CF, carry of the most significant bit.
    stp     x8, x9, [x22]

.LCalculateQ:
    ldr     x17 , [x2], #8           // b[i]
    ldr     x19, [sp]               // t[0]
    ldp     x15 , x16 , [x1], #16
    add     x22, sp , #8

    mul     x14 , x15 , x17            // a[0] * b[i]
    sub     x21, x5 , #16           // j = size-2
    umulh   x15 , x15 , x17
    ldp     x9, x10, [x3], #16
    mul     x6, x16 , x17            // a[1]*b[i]
    adds    x14 , x14 , x19
    umulh   x7, x16 , x17
    adc     x15 , x15 , xzr

    mul     x11, x14 , x4
    sub     x24, x24, #8            // i--

    umulh   x9, x9, x11
    mul     x12, x10, x11           // n[1] * t[0]*k0
    subs    xzr, x14 , #1
    umulh   x13, x10, x11
    cbz     x21,  .LReduceEnd

.LReduce:
    ldr     x16 , [x1], #8
    adc     x9, x9, xzr
    ldr     x19, [x22], #8          // t[j]
    adds    x14 , x6, x15
    sub     x21, x21, #8            // j--
    adc     x15 , x7, xzr

    adds    x8, x12, x9
    ldr     x10, [x3], #8
    adc     x9, x13, xzr

    mul     x6, x16 , x17            // a[j] * b[i]
    adds    x14 , x14 , x19
    umulh   x7, x16 , x17
    adc     x15 , x15 , xzr

    mul     x12, x10, x11           // n[j] * t[0]*k0
    adds    x8, x8, x14
    umulh   x13, x10, x11
    str     x8, [x22, #-16]        // t[j-1]
    cbnz    x21, .LReduce

.LReduceEnd:
    ldr     x19, [x22], #8
    adc     x9, x9, xzr
    adds    x14 , x6, x15
    sub     x1 , x1 , x5
    adc     x15 , x7, xzr

    adds    x8, x12, x9
    sub     x3 , x3 , x5            // x3 = &n[0]
    adcs    x9, x13, x23
    adc     x23, xzr, xzr

    adds    x14 , x14 , x19
    adc     x15 , x15 , xzr

    adds    x8, x8, x14
    adcs    x9, x9, x15
    adc     x23, x23, xzr           // x23 += CF, carry of the most significant bit.
    stp     x8, x9, [x22, #-16]

    cbnz    x24, .LCalculateQ

    ldr     x19, [sp]               // t[0]
    add     x22, sp , #8
    ldr     x10, [x3], #8           // n[0]
    subs    x21, x5 , #8
    mov     x1 , x0

.LSubMod:
    sbcs    x16 , x19, x10           // t[j] - n[j]
    ldr     x19, [x22], #8
    sub     x21, x21, #8            // j--
    ldr     x10, [x3], #8
    str     x16 , [x1], #8           // r[j] = t[j] - n[j]
    cbnz    x21,.LSubMod

    sbcs    x16 , x19, x10
    sbcs    x23, x23, xzr           // x23 -= CF
    str     x16 , [x1], #8           // r[size-1]

    ldr     x19, [sp]               // t[0]
    add     x22, sp , #8
    ldr     x16 , [x0], #8           // r[0]
    sub     x5 , x5 , #8            // size--

.LCondCopy:
    sub     x5 , x5 , #8            // size--
    csel    x10, x19, x16, lo
    ldr     x19, [x22], #8
    ldr     x16 , [x0], #8
    str     xzr, [x22, #-16]        // temporary space t[] clear to zero.
    str     x10, [x0 , #-16]
    cbnz    x5 , .LCondCopy

    csel    x10, x19, x16, lo
    str     xzr, [x22, #-8]         // temporary space t[] clear to zero.
    str     x10, [x0 , #-8]

    ldp     x23, x24, [x29, #16]
    mov     sp , x29
    ldp     x21, x22, [x29, #32]
    ldp     x19, x20, [x29, #48]
    ldr     x29, [sp], #64
    ret
.size   MontMul_Asm, .-MontMul_Asm

.type   MontSqr8, %function
MontSqr8:
    cmp     x1, x2
    b.ne    MontMul4

    stp     x29, x30, [sp, #-128]!  //  sp = sp - 128(Modify the SP and then save the SP.), [sp] = x29, [sp + 8] = x30,
                                    //  !Indicates modification sp
    add     x29, sp , #0            //  x29  = sp, The sp here has been reduced by 128.

    stp     x27, x28, [sp, #16]
    stp     x25, x26, [sp, #32]
    stp     x23, x24, [sp, #48]
    stp     x21, x22, [sp, #64]
    stp     x19, x20, [sp, #80]
    stp     x0 , x3 , [sp, #96]     // offload r and n, Push the pointers of r and n into the stack.

    ldp     x14 , x15 , [x1, #8*0]    // x14  = a[0], x15  = a[1]
    ldp     x16 , x17 , [x1, #8*2]    // x16  = a[2], x17  = a[3]
    ldp     x6, x7, [x1, #8*4]    // x6 = a[4], x7 = a[5]
    ldp     x8, x9, [x1, #8*6]    // x8 = a[6], x9 = a[7]

    sub     x2, sp, x5, lsl#4       // x2 = sp - 2*x5*8, x5 = size, x2 points to the start address of a 2*size memory. *8 is to convert to bytes
    lsl     x5, x5, #3              // x5 = x5 * 8, Converts size to bytes.
    mov     sp, x2                  // Alloca, Apply for Space.
    sub     x19, x5, #8*8           // x19 = x5(size * 8) - 64, 64 bytes is eight data blocks.
    b       .LZeroStart      // The lowest eight data blocks do not need to be cleared.
                             // x19 to x26 calculated in the first round are written to these eight data blocks.

.LZero:
    sub     x19, x19, #8*8          // Offset 64, cyclic increment.
    stp     xzr, xzr, [x2, #8*0]    // Clear the lower four data blocks.
    stp     xzr, xzr, [x2, #8*2]
    stp     xzr, xzr, [x2, #8*4]
    stp     xzr, xzr, [x2, #8*6]

.LZeroStart:                 // Clear the upper four data blocks.
    stp     xzr, xzr, [x2, #8*8]
    stp     xzr, xzr, [x2, #8*10]
    stp     xzr, xzr, [x2, #8*12]
    stp     xzr, xzr, [x2, #8*14]
    add     x2 , x2 , #8*16         // x2 points to the memory of 2*size.
                                    // Therefore, x27 offsets 8*8 each time, and x2 offsets 8*16 each time.
    cbnz    x19, .LZero       // x27(size) is used as the loop termination condition to clear the memory of 2 x size.
                              // When x19 = 0, the loop exits.

    add     x3 , x1 , x5            // x3 = x1 + bytes(size * 8)
    add     x1 , x1 , #8*8          // x1 = x1 + 64
    mov     x27, xzr
    mov     x28, xzr
    mov     x25, xzr
    mov     x26, xzr
    mov     x23, xzr
    mov     x24, xzr
    mov     x21, xzr
    mov     x22, xzr
    mov     x2 , sp                 // After clear to zero, assign sp back to x2.
    str     x4 , [x29, #112]        // [x29 + 112] = n0(x4)

.LOuterSqr8x:
    mul     x10, x14, x15             // a[0] * a[1~4]
    mul     x11, x14, x16             // keep cache hit ratio of x6
    mul     x12, x14, x17
    mul     x13, x14, x6

    adds    x28, x28, x10           // x27~x22 = t[0~7], x28 = t[1] = lo(a[0]*a[1]), adds is used to set CF to 0.
    mul     x10, x14 , x7           // lo(a[0] * a[5~7]), keep cache hit ratio of x14, the same below
    adcs    x25, x25, x11           // x10~x17 Used to save subsequent calculation results
    mul     x11, x14 , x8
    adcs    x26, x26, x12
    mul     x12, x14 , x9           // lo(a[0] * a[7])
    adcs    x23, x23, x13           // t[4] = lo(a[0] * a[4])

    umulh   x13, x14 , x15           // hi(a[0] * a[1~4]), Use x17 to keep the cache hit
    adcs    x24, x24, x10           // x24~x22 = t[5~7]
    umulh   x10, x14 , x16
    adcs    x21, x21, x11
    umulh   x11, x14 , x17
    adcs    x22, x22, x12           // t[7] += lo(a[0] * a[7]), Carrying has to be given t[8]
    umulh   x12, x14 , x6

    stp x27, x28, [x2], #8*2        // t[0] = a[0]^2, Because the square term is not calculated temporarily,
                                    // so t[0] = 0, t[1] = a[0] * a[1] + carry
    adc x27, xzr, xzr               // x27 = CF ( Set by t[7] += lo(a[0] * a[7]) ),
                                    // x19 is used to store t[8] (calculated intermediate result array t).
    // In the new round, the first calculation does not need to be carried, but the CF bit needs to be modified.
    adds    x25, x25, x13           // t[2] += hi(a[0] * a[1])
    umulh   x13, x14 , x7           // hi(a[0] * a[5~7])
    adcs    x26, x26, x10
    umulh   x10, x14 , x8
    adcs    x23, x23, x11
    umulh   x11, x14 , x9
    adcs    x24, x24, x12           // t[5] += hi(a[0] * a[4])

    //----- lo(a[1] * a[2~4]) ------
    mul     x12, x15 , x16            // lo(a[1] * a[2])
    adcs    x21, x21, x13           // t[6] += hi(a[0] * a[5])
    mul     x13, x15 , x17
    adcs    x22, x22, x10           // t[7] += hi(a[0] * a[6])
    mul     x10, x15 , x6
    adc     x27, x27, x11           // t[8] += hi(a[0] * a[7])

    //----- lo(a[1] * a[5~7]) ------
    mul     x11, x15 , x7
    adds    x26, x26, x12           // t[3] += lo(a[1] * a[2]), The first calculation of this round
                                    // does not take into account the previous carry, and the CF is not modified in line 118.
    mul     x12, x15 , x8
    adcs    x23, x23, x13           // t[4] += lo(a[1] * a[3])
    mul     x13, x15 , x9
    adcs    x24, x24, x10           // t[5] += lo(a[1] * a[4])

    //----- hi(a[1] * a[2~5]) ------
    umulh   x10, x15 , x16            // hi(a[1] * a[2])
    adcs    x21, x21, x11           // t[6] += lo(a[1] * a[5])
    umulh   x11, x15 , x17
    adcs    x22, x22, x12           // t[7] += lo(a[1] * a[6])
    umulh   x12, x15 , x6
    adcs    x27, x27, x13           // t[8] += lo(a[1] * a[7])
    umulh   x13, x15 , x7

    stp     x25, x26, [x2], #8*2        // t[2] and t[3] are calculated and stored in the memory.
                                        // x25 and x22 are used to store t[10] and t[11].
    adc     x28, xzr, xzr               // t[9] = CF ( Set by t[8] += lo(a[1] * a[7]) )
    //In the new round, the first calculation does not need to be carried, but the CF bit needs to be modified.
    //----- hi(a[1] * a[6~7]) ------
    adds    x23, x23, x10           // t[4] += hi(a[1] * a[2])
    umulh   x10, x15 , x8           // hi(a[1] * a[6])
    adcs    x24, x24, x11           // t[5] += hi(a[1] * a[3])
    umulh   x11, x15 , x9           // hi(a[1] * a[7])
    adcs    x21, x21, x12           // t[6] += hi(a[1] * a[4])

    //----- lo(a[2] * a[3~7]) ------
    mul     x12, x16 , x17            // lo(a[2] * a[3])
    adcs    x22, x22, x13           // t[7] += hi(a[1] * a[5])
    mul     x13, x16 , x6
    adcs    x27, x27, x10           // t[8] += hi(a[1] * a[6])
    mul     x10, x16 , x7
    adc     x28, x28, x11           // t[9] += hi(a[1] * a[7]), Here, only the carry of the previous round
                                    // of calculation is retained before x20 calculation. Add x15 to the carry.
    mul     x11, x16 , x8
    adds    x24, x24, x12           // t[5] += lo(a[2] * a[3]), For the first calculation of this round,
                                    // the previous carry is not considered.
    mul     x12, x16 , x9
    adcs    x21, x21, x13           // t[6] += lo(a[2] * a[4])

    //----- hi(a[2] * a[3~7]) ------
    umulh   x13, x16 , x17            // hi(a[2] * a[3])
    adcs    x22, x22, x10           // t[7] += lo(a[2] * a[5])
    umulh   x10, x16 , x6

    adcs    x27, x27, x11           // t[8] += lo(a[2] * a[6])
    umulh   x11, x16 , x7
    adcs    x28, x28, x12           // t[9] += lo(a[2] * a[7])
    umulh   x12, x16 , x8

    stp     x23, x24, [x2], #8*2    // After t[4] and t[5] are calculated, they are stored in the memory.
                                    // x23 and x24 are used to store t[12] and t[13].
    adc     x25, xzr, xzr           // t[10] = CF ( Set by t[9] += lo(a[2] * a[7]) )
    // In the new round, the first calculation does not need to be carried, but the CF bit needs to be modified.
    adds    x21, x21, x13           // t[6] += hi(a[2] * a[3])
    umulh   x13, x16 , x9
    adcs    x22, x22, x10           // t[7] += hi(a[2] * a[4])

    //----- lo(a[3] * a[4~7]) ------
    mul     x10, x17 , x6
    adcs    x27, x27, x11           // t[8] += hi(a[2] * a[5])
    mul     x11, x17 , x7
    adcs    x28, x28, x12           // t[9] += hi(a[2] * a[6])
    mul     x12, x17 , x8
    adc     x25, x25, x13           // t[10] += hi(a[2] * a[7])
    mul     x13, x17 , x9

    //----- hi(a[3] * a[4~7]) ------
    adds    x22, x22, x10           // t[7] += lo(a[3] * a[4])
    umulh   x10, x17 , x6
    adcs    x27, x27, x11           // t[8] += lo(a[3] * a[5])
    umulh   x11, x17 , x7
    adcs    x28, x28, x12           // t[9] += lo(a[3] * a[6])
    umulh   x12, x17 , x8
    adcs    x25, x25, x13           // t[10] += lo(a[3] * a[7])
    umulh   x13, x17 , x9

    stp     x21, x22, [x2], #8*2    // t[6] and t[7] are calculated and stored in the memory.
                                    // x21 and x26 are used to store t[14] and t[15].
    adc     x26, xzr, xzr           // t[11] = CF ( Set by t[10] += lo(a[3] * a[7]) )
    // In the new round, the first calculation does not need to be carried, but the CF bit needs to be modified.
    adds    x27, x27, x10           // t[8] += hi(a[3] * a[4])

    //----- lo(a[4] * a[5~7]) ------
    mul     x10, x6, x7
    adcs    x28, x28, x11           // t[9] += hi(a[3] * a[5])
    mul     x11, x6, x8
    adcs    x25, x25, x12           // t[10] += hi(a[3] * a[6])
    mul     x12, x6, x9
    adc     x26, x26, x13           // t[11] += hi(a[3] * a[7])

    //----- hi(a[4] * a[5~7]) ------
    umulh   x13, x6, x7
    adds    x28, x28, x10           // t[9] += lo(a[4] * a[5])
    umulh   x10, x6, x8
    adcs    x25, x25, x11           // t[10] += lo(a[4] * a[6])
    umulh   x11, x6, x9
    adcs    x26, x26, x12           // t[11] += lo(a[4] * a[7])

    //----- lo(a[5] * a[6~7]) ------
    mul     x12, x7, x8
    // This is actually a new round, but only t[0-7] can be calculated in each cycle,
    // and t[8-15] retains the intermediate calculation result.
    adc     x23, xzr, xzr           // t[12] = CF( Set by t[11] += lo(a[4] * a[7]) )
    adds    x25, x25, x13           // t[10] += hi(a[4] * a[5])
    mul     x13, x7, x9
    adcs    x26, x26, x10           // t[11] += hi(a[4] * a[6])

    //----- hi(a[5] * a[6~7]) ------
    umulh   x10, x7, x8
    adc     x23, x23, x11           // t[12] += hi(a[4] * a[7])
    umulh   x11, x7, x9

    adds    x26, x26, x12           // t[11] += lo(a[5] * a[6])
    //----- lo(a[6] * a[7]) ------
    mul     x12, x8, x9
    adcs    x23, x23, x13           // t[12] += lo(a[5] * a[7])

    //----- hi(a[6] * a[7])  ------
    umulh   x13, x8, x9
    adc     x24, xzr, xzr           // t[13] = CF ( Set by t[12] += lo(a[5] * a[7]) ),
                                    // This operation is required when a new umulh is added.
    adds    x23, x23, x10           // t[12] += hi(a[5] * a[6])

    adc     x24, x24, x11           // t[13] += hi(a[5] * a[7])
    adds    x24, x24, x12           // t[13] += lo(a[6] * a[7])

    adc     x21, xzr, xzr           // t[14] = CF ( set by t[13] += lo(a[6] * a[7]) )
    add     x21, x21, x13           // t[14] += hi(a[6] * a[7]), There must be no carry in the last step.

    sub     x19, x3, x1             // x3 = &a[size], x1 = &a[8], x19 = (size - 8) * 8
    sub     x10, x3, x5             // x10 = a, obtain the first address of array a again.

    cbz     x19, .LOuterBreak

    mov     x4 , x14                 // x4 = x14 = a[0]
    ldp     x14 , x15 , [x2, #8*0]    // x14  = t[8] , x15  = t[9]
    adds    x27, x27, x14            // t[8](t[8] reserved in the previous round of calculation) + = t[8]
                                     // (t[8] taken from memory, initially 0)
    adcs    x28, x28, x15            // t[9] += t[9], be the same as the above
    ldp     x14 , x15 , [x1, #8*0]    // x14 = a[8], x15 = a[9]

    ldp     x16 , x17 , [x2, #8*2]    // x16 = t[10], x17 = t[11]
    adcs    x25, x25, x16
    adcs    x26, x26, x17
    ldp     x16 , x17 , [x1, #8*2]    // x16 = a[10], x17 = a[11]

    ldp     x6, x7, [x2, #8*4]    // x6 = t[12], x7 = t[13]
    adcs    x23, x23, x6
    adcs    x24, x24, x7
    ldp     x6, x7, [x1, #8*4]    // x6 = a[12], x7 = a[13]

    ldp     x8, x9, [x2, #8*6]    // x8 = t[14], x9 = t[15]
    adcs    x21, x21, x8
    adcs    x22, xzr, x9           // t[15] = t[15] + CF, Because a[7]*a[7] is not calculated previously, t[15]=0
    ldp     x8, x9, [x1, #8*6]    // x8 = a[14], x9 = a[15]

    mov     x0, x1                  // x0 = &a[8]
    add     x1, x1, #8*8            // x1 = &a[16]
    mov     x19, #-8*8              // Loop range. x0 can retrieve a[0–7] based on this offset.

//########################################
//#          a[0~7] * a[8~15]            #
//########################################
.LMulSqr8x:
    //-----lo(a[0] * a[8~11])-----
    adc     x20, xzr, xzr           // x20 += CF, Save the carry of t[15]. The same operation is performed below.
    add     x19, x19, #8            // x19 += 8, Loop step size
    mul     x10, x4 , x14            // x4 = a[0], x14 = a[8], x10 = lo(a[0] * a[8])
    mul     x11, x4 , x15            // x11 = lo(a[0] * a[9])
    mul     x12, x4 , x16            // x12 = lo(a[0] * a[10])
    mul     x13, x4 , x17            // x13 = lo(a[0] * a[11])

    //-----lo(a[0] * a[12~15])-----
    adds    x27, x27, x10           // CF does not need to be added for the first calculation,
                                    // t[8] += lo(a[0] * a[8])
    mul     x10, x4 , x6
    adcs    x28, x28, x11           // t[9] += lo(a[0] * a[9])
    mul     x11, x4 , x7
    adcs    x25, x25, x12           // t[10] += lo(a[0] * a[10])
    mul     x12, x4 , x8
    adcs    x26, x26, x13           // t[11] += lo(a[0] * a[11])
    mul     x13, x4 , x9

    //-----hi(a[0] * a[8~11])-----
    adcs    x23, x23, x10           // t[12] += lo(a[0] * a[12])
    umulh   x10, x4 , x14
    adcs    x24, x24, x11           // t[13] += lo(a[0] * a[13])
    umulh   x11, x4 , x15
    adcs    x21, x21, x12           // t[14] += lo(a[0] * a[14])
    umulh   x12, x4 , x16
    adcs    x22, x22, x13           // t[15] += lo(a[0] * a[15])
    umulh   x13, x4 , x17

    adc     x20, x20, xzr           // x20 += CF, Save the carry of t[15]
    str     x27, [x2], #8           // [x2] = t[8], x2 += 8, x27~x22 = t[9~16],
                                    // Update the mapping relationship to facilitate cycling.
                                    // x27~x26 always correspond to t[m~m+7], and x19 is always the LSB of the window

    //-----hi(a[0] * a[12~15])-----
    adds    x27, x28, x10           // t[9] += hi(a[0] * a[8]), The last calculation was to calculate t[15],
                                    // so carry cannot be added to t[9], so adds is used
    umulh   x10, x4 , x6
    adcs    x28, x25, x11           // t[10] += hi(a[0] * a[9])
    umulh   x11, x4 , x7
    adcs    x25, x26, x12           // t[11] += hi(a[0] * a[10])
    umulh   x12, x4 , x8
    adcs    x26, x23, x13           // t[12] += hi(a[0] * a[11])
    umulh   x13, x4 , x9           // x13 = hi(a[0] * a[15])

    ldr     x4 , [x0, x19]          // x4 = [x0 + x19] = [x0 - 56] = [&a[8] - 56] = a[8 - 7] = a[1]

    adcs    x23, x24, x10           // t[13] += hi(a[0] * a[12])
    adcs    x24, x21, x11           // t[14] += hi(a[0] * a[13])
    adcs    x21, x22, x12           // t[15] += hi(a[0] * a[14])
    adcs    x22, x20, x13           // t[16] = hi(a[0] * a[15]) + CF

    cbnz    x19, .LMulSqr8x        // When exiting the loop, x0 = &a[8], x2 = &t[16]

    cmp     x1, x3                  // x3 = x1 + x5 * 8(Converted to bytes), When x1 = x3, the loop ends.
    b.eq    .LBreakSqr8x           // x0 is the outer loop, x1 is the inner loop, and the inner loop ends.
                                   // In this case, x2 = &a[size], out-of-bounds position.

    ldp     x14 , x15 , [x2, #8*0]    // x14  = t[16], x15  = t[17]
    adds    x27, x27, x14            // t[16]([16] reserved in the previous round of calculation) += t[16]
                                     // (t[16] fetched from memory, initially 0)
    adcs    x28, x28, x15            // t[17] += t[17], be the same as the above
    ldp     x14 , x15 , [x1, #8*0]    // x14  = a[16], x15  = a[17]
    ldp     x16 , x17 , [x2, #8*2]    // x16  = t[18], x17  = t[19]
    adcs    x25, x25, x16
    adcs    x26, x26, x17
    ldp     x16 , x17 , [x1, #8*2]    // x16  = a[18], x17  = a[19]
    ldp     x6, x7, [x2, #8*4]    // x6 = t[20], x7 = t[21]
    adcs    x23, x23, x6
    adcs    x24, x24, x7
    ldp     x6, x7, [x1, #8*4]    // x6 = a[20], x7 = a[21]
    ldp     x8, x9, [x2, #8*6]    // x8 = t[22], x9 = t[23]
    adcs    x21, x21, x8
    adcs    x22, x22, x9
    ldp     x8, x9, [x1, #8*6]    // x8 = a[22], x9 = a[23]

    ldr     x4 , [x0, #-8*8]        // x0 = &a[8], x4 = a[0]
    mov     x19, #-8*8              // x19 = -64, Set the loop termination condition again.
    add     x1 , x1 , #8*8          // x0 is the outer loop, and x1 is the inner loop.

    b       .LMulSqr8x

.align  4
.LBreakSqr8x:// The last set of data for the multiplication term operation
    ldp     x14 , x15 , [x0, #8*0]    // x14  = a[8] , x15  = a[9]
    ldp     x16 , x17 , [x0, #8*2]    // x16  = a[10], x17  = a[11]
    ldp     x6, x7, [x0, #8*4]    // x6 = a[12], x7 = a[13]
    ldp     x8, x9, [x0, #8*6]    // x8 = a[14], x9 = a[15]

    add     x1 , x0 , #8*8          // Outer Loop Increment, x1 = &a[16]
    sub     x10, x3 , x1            // Check whether the outer loop ends, x3 = &a[size], x10 = (size - 16)*8
    sub     x11, x2 , x10           // x2 = &t[24], x11 = &t[16]
    cbz     x10, .LOuterSqr8x



    stp     x27, x28, [x2 , #8*0]   // t[24] = x27, t[25] = x28
    ldp     x27, x28, [x11, #8*0]   // x27 = t[16], x28 = t[17]

    stp     x25, x26, [x2 , #8*2]   // t[26] = x25, t[27] = x26
    ldp     x25, x26, [x11, #8*2]   // x25 = t[18], x26 = t[19]

    stp     x23, x24, [x2 , #8*4]   // t[28] = x23, t[29] = x24
    ldp     x23, x24, [x11, #8*4]   // x23 = t[20], x24 = t[21]

    stp     x21, x22, [x2 , #8*6]   // t[30] = x21, t[31] = x22
    ldp     x21, x22, [x11, #8*6]   // x21 = t[22], x22 = t[23]

    mov     x2 , x11                // x2 = &t[16]
    b       .LOuterSqr8x

.align  4
.LOuterBreak:
    //===== Calculate the squared term =====
    //----- x10 = &a[0], sp = &t[0] , x2 = &t[24]-----
    ldp     x15 , x17 , [x10, #8*0]   // x15  = a[0], x17  = a[1]
    ldp     x7, x9, [x10, #8*2]    // x7 = a[2], x9 = a[3]

    ldp     x11, x12, [sp, #8*1]    // x11 = t[1], x12 = t[2]
    add     x1 , x10, #8*4          // x1  = &a[4]
    ldp     x13, x10, [sp, #8*3]    // x13 = t[3], x10 = t[4]

    stp     x27, x28, [x2, #8*0]    // t[24] = x27, t[25] = x28
    stp     x25, x26, [x2, #8*2]    // When this step is performed, the calculation results reserved for x27–x26
                                    // are not pushed to the stack.
    stp     x23, x24, [x2, #8*4]
    stp     x21, x22, [x2, #8*6]
    mul     x27, x15 , x15            // x27 = lo(a[0] * a[0])
    umulh   x15 , x15 , x15            // x15  = hi(a[0] * a[0])
    mul     x16 , x17 , x17            // x16  = lo(a[1] * a[1])
    umulh   x17 , x17 , x17            // x17  = hi(a[1] * a[1])

    mov     x2 , sp                 // x2 = sp = &t[0]

    adds    x28, x15 , x11, lsl#1    // x28 = x15 + (x11 * 2) = hi(a[0] * a[0]) + 2 * t[1]
    extr    x11, x12, x11, #63      // Lower 63 bits of x11 = x16 | most significant bit of x15
                                    // Cyclic right shift by 63 bits to obtain the lower bit,
                                    // which is equivalent to cyclic left shift by 1 bit to obtain the upper bit.
                                    // The purpose is to *2.
                                    // x11 = 2*t[2](Ignore the overflowed part) + carry of (2*t[1])
    sub     x19, x5 , #8*4          // x5 = size*8, x19 = (size - 4)*8

.LShiftAddSqr4x:
    adcs    x25, x16 , x11           // x25 = lo(a[1] * a[1]) + 2*t[2]
    extr    x12, x13, x12, #63      // x12 = 2*t[3](Ignore the overflowed part) + carry of (2*t[2])
    adcs    x26, x17 , x12           // x26 = hi(a[1] * a[1]) + 2*t[3]

    stp     x27, x28, [x2, #8*0]    // t[0~3]Re-push stack
    stp     x25, x26, [x2, #8*2]

    sub     x19, x19, #8*4          // x19 = (size - 8)*8

    ldp     x11, x12, [x2, #8*5]    // x11 = t[5], x12 = t[6]

    mul     x6, x7, x7           // x6 = lo(a[2] * a[2])
    umulh   x7, x7, x7           // x7 = hi(a[2] * a[2])
    mul     x8, x9, x9           // x6 = lo(a[3] * a[3])
    umulh   x9, x9, x9           // x7 = hi(a[3] * a[3])

    extr    x13, x10, x13, #63      // x13 = 2*t[4](Ignore the overflowed part) + carry of(2*t[3])
    adcs    x23, x6, x13           // x23 = lo(a[2] * a[2]) + 2*t[4]
    extr    x10, x11, x10, #63      // x10 = 2*t[5](Ignore the overflowed part) + carry of(2*t[4])
    adcs    x24, x7, x10           // x24 = hi(a[2] * a[2]) + 2*t[5]

    ldp     x13, x10, [x2, #8*7]    // x13 = t[7], x10 = t[8]
    extr    x11, x12, x11, #63      // x11 = 2*t[6](Ignore the overflowed part) + carry of(2*t[5])
    adcs    x21, x8, x11           // x21 = lo(a[3] * a[3]) + 2*t[6]
    extr    x12, x13, x12, #63      // x12 = 2*t[7](Ignore the overflowed part) + carry of(2*t[6])
    adcs    x22, x9, x12           // x22 = hi(a[3] * a[3]) + 2*t[7]

    ldp     x11, x12, [x2, #8*9]    // x11 = t[9], x12 = t[10]

    ldp     x15 , x17 , [x1], #8*2    // x15  = a[4], x17  = a[5], x1 += 16 = &a[6]

    mul     x14 , x15 , x15            // x14  = lo(a[4] * a[4])
    umulh   x15 , x15 , x15            // x15  = hi(a[4] * a[4])
    mul     x16 , x17 , x17            // x16  = lo(a[5] * a[5])
    umulh   x17 , x17 , x17            // x17  = hi(a[5] * a[5])

    stp     x23, x24, [x2, #8*4]    // t[4~7]re-push stack
    stp     x21, x22, [x2, #8*6]
    add     x2 , x2 , #8*8          // x2 = &t[8]

    extr    x13, x10, x13, #63      // x13 = 2*t[8](Ignore the overflowed part) + carry of(2*t[7])
    adcs    x27, x14 , x13           // x27 = lo(a[4] * a[4]) + 2*t[8]
    extr    x10, x11, x10, #63      // x10 = 2*t[9](Ignore the overflowed part) + carry of(2*t[8])
    adcs    x28, x15 , x10           // x28 = hi(a[4] * a[4]) + 2*t[9]

    extr    x11, x12, x11, #63      // x11 = 2*t[10](Ignore the overflowed part) + carry of(2*t[9])

    ldp     x13, x10, [x2, #8*3]    // Line 438 has obtained t[9] and t[10], x13 = &t[11], x10 = &t[12]
    ldp     x7, x9, [x1], #8*2    // x7 = a[6], x9 = a[7], x1 += 16 = &a[8]

    cbnz    x19, .LShiftAddSqr4x

    // When x19=0, the last round of calculation is missing.
    //----- x2 = &t[2*size-8] -----
    adcs    x25, x16 , x11           // x25 = lo(a[size-3] * a[size-3]) + 2*t[2*size-6]
    extr    x12, x13, x12, #63      // x12 = 2*t[2*size-5](Ignore the overflowed part) + carry of (2*t[2*size-6])
    adcs    x26, x17 , x12           // x26 = hi(a[size-3] * a[size-3]) + 2*t[2*size-5]

    stp     x27, x28, [x2, #8*0]    // t[2*size-8 ~ 2*size-5]re-push stack
    stp     x25, x26, [x2, #8*2]

    ldp     x11, x12, [x2, #8*5]    // x11 = t[2*size-3], x12 = t[2*size-2]

    mul     x6, x7, x7           // x6 = lo(a[size-2] * a[size-2])
    umulh   x7, x7, x7           // x7 = hi(a[size-2] * a[size-2])
    mul     x8, x9, x9           // x6 = lo(a[size-1] * a[size-1])
    umulh   x9, x9, x9           // x7 = hi(a[size-1] * a[size-1])

    extr    x13, x10, x13, #63      // x13 = 2*t[2*size-4](Ignore the overflowed part) + carry of (2*t[2*size-5])
    adcs    x23, x6, x13           // x23 = lo(a[size-2] * a[size-2]) + 2*t[2*size-4]
    extr    x10, x11, x10, #63      // x10 = 2*t[2*size-3](Ignore the overflowed part) + carry of (2*t[2*size-4])
    adcs    x24, x7, x10           // x24 = hi(a[size-2] * a[size-2]) + 2*t[2*size-3]

    extr    x11, x12, x11, #63      // x11 = 2*t[2*size-2](Ignore the overflowed part) + carry of (2*t[2*size-3])
    adcs    x21, x8, x11           // x21 = lo(a[size-1] * a[size-1]) + 2*t[2*size-2]
    extr    x12, xzr, x12, #63      // x12 = 2*t[2*size-1](Ignore the overflowed part) + carry of (2*t[2*size-2])
    adc     x22, x9, x12           // x22 = hi(a[size-1] * a[size-1]) + 2*t[2*size-1]

    ldp     x1 , x4 , [x29,#104]    // Pop n and k0 out of the stack, x1 = &n[0], x4 = k0
    ldp     x27, x28, [sp]          // x27 = t[0], x28 = t[1]

    ldp     x14 , x15 , [x1, #8*0]    // x14~x9 = n[0~7]
    ldp     x16 , x17 , [x1, #8*2]
    ldp     x6, x7, [x1, #8*4]
    ldp     x8, x9, [x1, #8*6]

    mul     x20, x4 , x27           // x20 = lo(k0 * t[0])
    add     x3 , x1 , x5            // x3 = &n[size]

    ldp     x25, x26, [sp,#8*2]     // x25~x22 = t[2~7]
    stp     x23, x24, [x2,#8*4]     // t[2*size-4 ~ 2*size-1]re-push stack
    ldp     x23, x24, [sp,#8*4]
    stp     x21, x22, [x2,#8*6]
    ldp     x21, x22, [sp,#8*6]

    add     x1 , x1 , #8*8
    mov     x30, xzr
    mov     x2 , sp
    mov     x19, #8

.LReduceSqr8x:
    sub     x19, x19, #1
    //----- lo(n[1~7] * lo(t[0]*k0)) -----
    mul     x11, x15 , x20           // x11 = n[1] * lo(t[0]*k0)
    mul     x12, x16 , x20           // x12 = n[2] * lo(t[0]*k0)
    mul     x13, x17 , x20           // x13 = n[3] * lo(t[0]*k0)
    mul     x10, x6, x20           // x10 = n[4] * lo(t[0]*k0)

    str     x20, [x2], #8           // Push lo(t[0]*k0) on the stack., x2 += 8
    subs    xzr, x27, #1            // xzr cannot be written, so only the symbol of x19-1 is taken here.

    adcs    x27, x28, x11           // x27 = t[1] + lo(n[1] * lo(t[0]*k0))
    mul     x11, x7, x20
    adcs    x28, x25, x12           // x28 = t[2] + lo(n[2] * lo(t[0]*k0))
    mul     x12, x8, x20
    adcs    x25, x26, x13           // x25 = t[3] + lo(n[3] * lo(t[0]*k0))
    mul     x13, x9, x20
    adcs    x26, x23, x10           // x26 = t[4] + lo(n[4] * lo(t[0]*k0))

    //----- hi(n[0~7] * lo(t[0]*k0)) -----
    umulh   x10, x14 , x20
    adcs    x23, x24, x11           // x23 = t[5] + lo(n[5] * lo(t[0]*k0))
    umulh   x11, x15 , x20
    adcs    x24, x21, x12           // x24 = t[6] + lo(n[6] * lo(t[0]*k0))
    umulh   x12, x16 , x20
    adcs    x21, x22, x13           // x21 = t[7] + lo(n[7] * lo(t[0]*k0))
    umulh   x13, x17 , x20
    adc     x22, xzr, xzr           // x22 += CF

    adds    x27, x27, x10           // x27 += hi(n[0] * lo(t[0]*k0))
    umulh   x10, x6, x20
    adcs    x28, x28, x11           // x28 += hi(n[1] * lo(t[0]*k0))
    umulh   x11, x7, x20
    adcs    x25, x25, x12           // x25 += hi(n[2] * lo(t[0]*k0))
    umulh   x12, x8, x20
    adcs    x26, x26, x13           // x26 += hi(n[3] * lo(t[0]*k0))
    umulh   x13, x9, x20

    adcs    x23, x23, x10           // x23 += hi(n[4] * lo(t[0]*k0))
    adcs    x24, x24, x11           // x24 += hi(n[5] * lo(t[0]*k0))
    adcs    x21, x21, x12           // x21 += hi(n[6] * lo(t[0]*k0))
    adc     x22, x22, x13           // x22 += hi(n[7] * lo(t[0]*k0))

    mul     x20, x4 , x27           // x20 = lo(k0 * t[i])

    cbnz    x19, .LReduceSqr8x   // Cycle 8 times, and at the end of the cycle, x2 += 8*8

    ldp     x10, x11, [x2, #8*0]    // x10 = t[8], x11 = t[9]
    ldp     x12, x13, [x2, #8*2]
    mov     x0, x2
    sub     x19, x3 , x1            // x3 = &n[size], x1 = &n[8]

    adds    x27, x27, x10
    adcs    x28, x28, x11
    ldp     x10, x11, [x2,#8*4]
    adcs    x25, x25, x12
    adcs    x26, x26, x13
    ldp     x12, x13, [x2,#8*6]
    adcs    x23, x23, x10
    adcs    x24, x24, x11
    adcs    x21, x21, x12
    adcs    x22, x22, x13
    cbz     x19, .LEndSqr8x

    ldr     x4 , [x2, #-8*8]        // x4 = t[0]
    ldp     x14 , x15 , [x1, #8*0]    // x14~x9 = &n[8]~&n[15]
    ldp     x16 , x17 , [x1, #8*2]
    ldp     x6, x7, [x1, #8*4]
    ldp     x8, x9, [x1, #8*6]
    add     x1 , x1 , #8*8          // x1 = &n[16]
    mov     x19, #-8*8

.LLastSqr8x:
    adc     x20, xzr, xzr           // x20 = CF
    add     x19, x19, #8

    mul     x10, x14 , x4
    mul     x11, x15 , x4
    mul     x12, x16 , x4
    mul     x13, x17 , x4

    adds    x27, x27, x10
    mul     x10, x6, x4
    adcs    x28, x28, x11
    mul     x11, x7, x4
    adcs    x25, x25, x12
    mul     x12, x8, x4
    adcs    x26, x26, x13
    mul     x13, x9, x4

    adcs    x23, x23, x10
    umulh   x10, x14 , x4
    adcs    x24, x24, x11
    umulh   x11, x15 , x4
    adcs    x21, x21, x12
    umulh   x12, x16 , x4
    adcs    x22, x22, x13
    umulh   x13, x17 , x4

    adc     x20, x20, xzr

    str     x27, [x2], #8           // x27 = t[8], x2 += 8

    adds    x27, x28, x10           // x27 = t[1] + lo(n[1] * lo(t[0]*k0))
    umulh   x10, x6, x4
    adcs    x28, x25, x11           // x28 = t[2] + lo(n[2] * lo(t[0]*k0))
    umulh   x11, x7, x4
    adcs    x25, x26, x12           // x25 = t[3] + lo(n[3] * lo(t[0]*k0))
    umulh   x12, x8, x4
    adcs    x26, x23, x13           // x26 = t[4] + lo(n[4] * lo(t[0]*k0))
    umulh   x13, x9, x4

    // x0 = &t[8]
    ldr     x4 , [x0, x19]

    adcs    x23, x24, x10
    adcs    x24, x21, x11
    adcs    x21, x22, x12
    adcs    x22, x20, x13

    cbnz    x19, .LLastSqr8x

    ldp     x14 , x15 , [x2, #8*0]
    ldp     x16 , x17 , [x2, #8*2]
    ldp     x6, x7, [x2, #8*4]
    ldp     x8, x9, [x2, #8*6]

    sub     x12, x3 , x5            // x12 = n, reassign to n
    sub     x19, x3 , x1            // x19 = (size-16)*8

    cbz     x19, .LLastBreakSqr8x

    ldr     x4 , [x0, #-8*8]

    adds    x27, x27, x14
    adcs    x28, x28, x15
    adcs    x25, x25, x16
    adcs    x26, x26, x17
    adcs    x23, x23, x6
    adcs    x24, x24, x7
    adcs    x21, x21, x8
    adcs    x22, x22, x9

    ldp     x14 , x15 , [x1, #8*0]
    ldp     x16 , x17 , [x1, #8*2]
    ldp     x6, x7, [x1, #8*4]
    ldp     x8, x9, [x1, #8*6]

    add     x1 , x1 , #8*8
    mov     x19, #-8*8

    b       .LLastSqr8x


.align  4
.LLastBreakSqr8x:
    ldr     x4 , [x29, #112]        // k0 pop-stack
    add     x19, x2 , #8*8          // x19 = &t[2*size]

    subs    xzr, x30, #1            // xzr cannot be written. The symbol of x30-1 is used.

    adcs    x10, x27, x14
    adcs    x11, x28, x15
    stp     x10, x11, [x2 , #8*0]

    ldp     x27 ,x28, [x0 , #8*0]
    ldp     x14 , x15 , [x12, #8*0]   // x12 = &n[0] (Line 638 assigns a value)

    adcs    x25, x25, x16
    adcs    x26, x26, x17
    ldp     x16 , x17 , [x12, #8*2]

    adcs    x23, x23, x6
    adcs    x24, x24, x7
    ldp     x6, x7, [x12, #8*4]

    adcs    x21, x21, x8
    adcs    x22, x22, x9
    ldp     x8, x9, [x12, #8*6]

    add     x1 , x12, #8*8
    adc     x30, xzr, xzr

    mul     x20, x4 , x27

    stp     x25, x26, [x2, #8*2]
    ldp     x25, x26, [x0, #8*2]

    stp     x23, x24, [x2, #8*4]
    ldp     x23, x24, [x0, #8*4]

    stp     x21, x22, [x2, #8*6]
    ldp     x21, x22, [x0, #8*6]

    mov     x2 , x0                 // sliding window
    cmp     x19, x29                // Check whether the loop ends
    mov     x19, #8
    b.ne    .LReduceSqr8x

    // Final step
    ldr     x0 , [x29, #96]         // r Pop-Stack
    add     x2 , x2 , #8*8
    subs    x10, x27, x14
    sbcs    x11, x28, x15
    sub     x19, x5 , #8*8
    mov     x3 , x0                 // backup x0

.LSubSqr8x:
    ldp     x14 , x15 , [x1, #8*0]

    sbcs    x12, x25, x16
    sbcs    x13, x26, x17
    ldp     x16 , x17 , [x1, #8*2]
    stp     x12, x13, [x0, #8*2]

    stp     x10, x11, [x0, #8*0]
    sbcs    x10, x23, x6
    sbcs    x11, x24, x7
    ldp     x6, x7, [x1, #8*4]

    sbcs    x12, x21, x8
    sbcs    x13, x22, x9
    ldp     x8, x9, [x1, #8*6]

    stp     x10, x11, [x0, #8*4]
    stp     x12, x13, [x0, #8*6]

    add     x1 , x1 , #8*8

    ldp     x27, x28, [x2, #8*0]
    ldp     x25, x26, [x2, #8*2]
    ldp     x23, x24, [x2, #8*4]
    ldp     x21, x22, [x2, #8*6]

    add     x2 , x2 , #8*8
    sbcs    x10, x27, x14
    add     x0 , x0 , #8*8
    sbcs    x11, x28, x15

    sub     x19, x19, #8*8
    cbnz    x19, .LSubSqr8x

    mov     x2 , sp
    add     x1 , sp , x5

    ldp     x14 , x15 , [x3, #8*0]

    sbcs    x12, x25, x16
    sbcs    x13, x26, x17
    ldp     x16 , x17 , [x3, #8*2]
    stp     x12, x13, [x0, #8*2]

    stp     x10, x11, [x0, #8*0]
    sbcs    x10, x23, x6
    sbcs    x11, x24, x7
    stp     x10, x11, [x0, #8*4]

    sbcs    x12, x21, x8
    sbcs    x13, x22, x9
    stp     x12, x13, [x0, #8*6]

    ldp     x27, x28, [x1, #8*0]
    ldp     x25, x26, [x1, #8*2]
    sbcs    xzr, x30, xzr           // Determine whether there is a borrowing
    ldr     x30, [x29, #8]          // x30 Pop-Stack

    sub     x19, x5 , #8*4

.LCopySqr4x:
    sub     x19, x19, #8*4
    csel    x10, x27, x14 , lo        // Condition selection instruction, lo = less than,
                                      // equivalent to x14 = (conf==lo) ? x27 : x14
    stp     xzr, xzr, [x2, #8*0]
    csel    x11, x28, x15 , lo
    ldp     x14 , x15 , [x3, #8*4]
    ldp     x27, x28, [x1, #8*4]

    csel    x12, x25, x16 , lo
    stp     xzr, xzr, [x2,#8*2]
    add     x2 , x2 , #8*4
    csel    x13, x26, x17 , lo
    ldp     x16 , x17 , [x3,#8*6]
    ldp     x25, x26, [x1,#8*6]
    add     x1 , x1 , #8*4
    stp     x10, x11, [x3,#8*0]
    stp     x12, x13, [x3,#8*2]
    add     x3 , x3 , #8*4

    stp     xzr, xzr, [x1,#8*0]
    stp     xzr, xzr, [x1,#8*2]
    cbnz    x19, .LCopySqr4x

    csel    x10, x27, x14 , lo
    stp     xzr, xzr, [x2, #8*0]
    csel    x11, x28, x15 , lo
    stp     xzr, xzr, [x2, #8*2]
    csel    x12, x25, x16 , lo
    csel    x13, x26, x17 , lo
    stp     x10, x11, [x3, #8*0]
    stp     x12, x13, [x3, #8*2]

    b       .BnMontSqr8xEnd

.align  4
.LEndSqr8x:
    adc     x20, xzr, xzr
    ldr     x30, [x29, #8]          // x30 Pop-Stack
    subs    x14 , x27, x14
    ldr     x1 , [x29, #96]         // r Pop-Stack
    sbcs    x15 , x28, x15
    stp     xzr, xzr, [sp,#8*0]
    sbcs    x16 , x25, x16
    stp     xzr, xzr, [sp,#8*2]
    sbcs    x17 , x26, x17
    stp     xzr, xzr, [sp,#8*4]
    sbcs    x6, x23, x6
    stp     xzr, xzr, [sp,#8*6]
    sbcs    x7, x24, x7
    stp     xzr, xzr, [sp,#8*8]
    sbcs    x8, x21, x8
    stp     xzr, xzr, [sp,#8*10]
    sbcs    x9, x22, x9
    stp     xzr, xzr, [sp,#8*12]
    sbcs    x20, x20, xzr           // determine whether there is a borrowing
    stp     xzr, xzr, [sp,#8*14]

    // x14-7 hold result-modulus
    csel    x14 , x27, x14 , lo
    csel    x15 , x28, x15 , lo
    csel    x16 , x25, x16 , lo
    csel    x17 , x26, x17 , lo
    stp     x14 , x15 , [x1, #8*0]
    csel    x6, x23, x6, lo
    csel    x7, x24, x7, lo
    stp     x16 , x17 , [x1, #8*2]
    csel    x8, x21, x8, lo
    csel    x9, x22, x9, lo
    stp     x6, x7, [x1, #8*4]
    stp     x8, x9, [x1, #8*6]

.BnMontSqr8xEnd:
    ldp     x27, x28, [x29, #16]
    mov     sp ,  x29
    ldp     x25, x26, [x29, #32]
    mov     x0 ,  #1
    ldp     x23, x24, [x29, #48]
    ldp     x21, x22, [x29, #64]
    ldp     x19, x20, [x29, #80]    // x19 = [x29 + 80], x20 = [x29 + 80 + 8],
                                    // ldp reads two 8-byte memory blocks at a time.
    ldr     x29, [sp], #128         // x29 = [sp], sp = sp + 128,ldr reads only an 8-byte block of memory
    ret
.size   MontSqr8, .-MontSqr8


.type   MontMul4, %function
MontMul4:
    stp     x29, x30, [sp, #-128]!
    add     x29, sp , #0
    stp     x27, x28, [sp, #16]
    stp     x25, x26, [sp, #32]
    stp     x23, x24, [sp, #48]
    stp     x21, x22, [sp, #64]
    stp     x19, x20, [sp, #80]

    lsl     x5 , x5 , #3
    sub     x22, sp , x5
    sub     sp , x22, #8*4          // The space of size + 4 is applied for

    add     x6, x2 , x5            // x6 = &b[size]
    add     x19, x1 , x5            // x19 = &a[size]
    stp     x0 , x6, [x29, #96]    // r and &b[size] push stack

    ldr     x24, [x2]               // x24 = b[0]
    ldp     x14 , x15 , [x1, #8*0]
    ldp     x16 , x17 , [x1, #8*2]    // x14~x17 = a[0~3]
    add     x1 , x1 , #8*4          // x1 = &a[4]

    mov     x27, xzr
    mov     x28, xzr
    mov     x25, xzr
    mov     x26, xzr
    ldp     x10, x11, [x3]          // x10~x13 = n[0~3]
    ldp     x12, x13, [x3, #8*2]
    adds    x3 , x3 , #8*4          // x3 = &n[4], CF set to 0

    mov     x0 , xzr
    mov     x20, #0
    mov     x22, sp

.L1stReduceMul4x:
    //----- lo(a[0~3] * b[0]) -----
    adc     x0 , x0 , xzr           // x0 += CF
    add     x20, x20, #8
    and     x20, x20, #31           // x20 &= 0xff. The lower eight bits are used.
                                    // When x28 = 32, the instruction becomes 0.

    mul     x6, x14 , x24
    mul     x7, x15 , x24
    mul     x8, x16 , x24
    mul     x9, x17 , x24

    //----- hi(a[0~3] * b[0]) -----
    adds    x27, x27, x6           // t[0] += lo(a[0] * b[0])
    umulh   x6, x14 , x24           // x6 = hi(a[0] * b[0])
    adcs    x28, x28, x7           // t[1] += lo(a[1] * b[0])
    umulh   x7, x15 , x24
    adcs    x25, x25, x8           // t[2] += lo(a[2] * b[0])
    umulh   x8, x16 , x24
    adcs    x26, x26, x9           // t[3] += lo(a[3] * b[0])
    umulh   x9, x17 , x24

    mul     x21, x27, x4            // x21 = t[0] * k0, t[0]*k0 needs to be recalculated in each round.
                                    // t[0] is different in each round.
    adc     x23, xzr, xzr           // t[4] += CF(set by t[3] += lo(a[3] * b[0]) )

    ldr     x24, [x2, x20]          // b[i]

    str     x21, [x22], #8          // t[0] * k0 push stack, x22 += 8

    //----- lo(n[1~3] * t[0]*k0) -----
    //mul     x6, x10, x21
    adds    x28, x28, x6           // t[1] += hi(a[0] * b[0])
    adcs    x25, x25, x7           // t[2] += hi(a[1] * b[0])
    mul     x7, x11, x21           // x7 = lo(n[1] * t[0]*k0)
    adcs    x26, x26, x8           // t[3] += hi(a[2] * b[0])
    mul     x8, x12, x21           // x8 = lo(n[2] * t[0]*k0)
    adc     x23, x23, x9           // t[4] += hi(a[3] * b[0])
    mul     x9, x13, x21           // x9 = lo(n[3] * t[0]*k0)

    //----- hi(n[0~3] *t[0]*k0) -----
    subs    xzr, x27, #1            // Take the symbol of x19-1
    umulh   x6, x10, x21           // x6 = hi(n[0] * t[0]*k0)
    adcs    x27, x28, x7           // (t[0]) = x27 = t[1] + lo(n[1] * t[0]*k0),
                                   // Perform S/R operations, r=2^64, shift right 64 bits.
    umulh   x7, x11, x21           // x7 = hi(n[1] * t[0]*k0)
    adcs    x28, x25, x8           // x28 = t[2] + lo(n[2] * t[0]*k0)
    umulh   x8, x12, x21           // x8 = hi(n[2] * t[0]*k0)
    adcs    x25, x26, x9           // x25 = t[3] + lo(n[3] * t[0]*k0)
    umulh   x9, x13, x21           // x9 = hi(n[3] * t[0]*k0)
    adcs    x26, x23, x0            // x26 = t[4] + 0 + CF
    adc     x0 , xzr, xzr           // x0 = CF

    adds    x27, x27, x6           // x27 = t[1] + hi(n[0] * t[0]*k0)
    adcs    x28, x28, x7           // x28 = t[2] + hi(n[1] * t[0]*k0)
    adcs    x25, x25, x8           // x25 = t[3] + hi(n[2] * t[0]*k0)
    adcs    x26, x26, x9           // x26 = t[4] + hi(n[3] * t[0]*k0)

    sub     x6, x19, x1            // x6 = &a[size] - &a[4] (The value of x1 increases cyclically)

    cbnz    x20, .L1stReduceMul4x
    // Four t[0] * k0s are stacked in each loop.

    cbz     x6, .LEndCondMul4x

    ldp     x14 , x15 , [x1]          // x14~x17 = a[4~7]
    ldp     x16 , x17 , [x1, #8*2]

    add     x1 , x1 , #8*4          // x1 += 4, the first time you come to this step, x1 = &a[8]
    ldr     x21, [sp]               // x21 = t[0] * k0
    ldp     x10, x11, [x3]          // x10~x13 = n[4~7]
    ldp     x12, x13, [x3, #8*2]
    add     x3 , x3 , #8*4

.L1stLastMul4x:
    adc     x0 , x0 , xzr
    add     x20, x20, #8
    and     x20, x20, #31
    //----- lo(a[4~7] * b[i]) -----
    mul     x6, x14 , x24
    mul     x7, x15 , x24
    mul     x8, x16 , x24
    mul     x9, x17 , x24

    //----- hi(a[4~7] * b[i]) -----
    adds    x27, x27, x6           // x27 += lo(a[4~7] * b[i])
    umulh   x6, x14 , x24
    adcs    x28, x28, x7
    umulh   x7, x15 , x24
    adcs    x25, x25, x8
    umulh   x8, x16 , x24
    adcs    x26, x26, x9
    umulh   x9, x17 , x24
    adc     x23, xzr, xzr

    ldr     x24, [x2, x20]          // b[i]

    //----- lo(n[4~7] * t[0]*k0) -----
    adds    x28, x28, x6
    adcs    x25, x25, x7
    adcs    x26, x26, x8
    adc     x23, x23, x9
    mul     x6, x10, x21
    mul     x7, x11, x21
    mul     x8, x12, x21
    mul     x9, x13, x21

    //----- hi(n[4~7] * t[0]*k0) -----
    adds    x27, x27, x6
    adcs    x28, x28, x7
    adcs    x25, x25, x8
    adcs    x26, x26, x9
    adcs    x23, x23, x0
    umulh   x6, x10, x21
    umulh   x7, x11, x21
    umulh   x8, x12, x21
    umulh   x9, x13, x21

    ldr     x21, [sp, x20]          // t[0]*k0

    adc     x0 , xzr, xzr           // x0 = CF, record carry
    str     x27, [x22], #8          // s[i] the calculation is complete, write the result, x22 += 8

    adds    x27, x28, x6
    adcs    x28, x25, x7
    adcs    x25, x26, x8
    adcs    x26, x23, x9

    sub     x6, x19, x1            // x6 = &a[size] - &a[i]
                                   // (The value of x1 increases cyclically.) Check whether the loop ends.

    cbnz    x20, .L1stLastMul4x

    sub     x7, x19, x5            // x7 = &a[0]
    cbz     x6, .LMul4x

    ldp     x14 , x15 , [x1, #8*0]
    ldp     x16 , x17 , [x1, #8*2]
    add     x1 , x1 , #8*4
    ldp     x10, x11, [x3, #8*0]
    ldp     x12, x13, [x3, #8*2]
    add     x3 , x3 , #8*4          // The n subscript is offset once by 4, x3 = &n[4], followed by &n[8], &n[12]...
    b       .L1stLastMul4x

.align  5
.LMul4x:
    ldr     x24, [x2, #8*4]!        // The b subscript is offset once by 4, x2 = &b[4], followed by &b[8], &b[12]...
    adc     x30, x0 , xzr
    ldp     x14 , x15 , [x7, #8*0]   // a[0~3]
    ldp     x16 , x17 , [x7, #8*2]
    sub     x3 , x3 , x5            // x3 = &n[0]
    add     x1 , x7, #8*4

    stp     x27, x28, [x22, #8*0]   // s the calculation is complete, write the result.
    ldp     x27, x28, [sp, #8*4]    // t[0~3]
    stp     x25, x26, [x22, #8*2]   // s the calculation is complete, write the result.
    ldp     x25, x26, [sp, #8*6]
    mov     x22, sp

    ldp     x10, x11, [x3, #8*0]    // n[0~3]
    ldp     x12, x13, [x3, #8*2]
    adds    x3 , x3 , #8*4          // n Subscript one-time offset 4, CF clear to zero
    mov     x0 , xzr

.align  4
.LReduceMul4x:
    adc     x0 , x0 , xzr           // x0 += CF
    add     x20, x20, #8            // x20 += 8, cyclic increment
    and     x20, x20, #31           // When x28 increases to 32, x20 = 0, and data is grouped in sets of four.
    //----- lo(a[0~3] * b[4]) -----
    mul     x6, x14 , x24
    mul     x7, x15 , x24
    mul     x8, x16 , x24
    mul     x9, x17 , x24

    adds    x27, x27, x6
    adcs    x28, x28, x7
    adcs    x25, x25, x8
    adcs    x26, x26, x9
    adc     x23, xzr, xzr           // x23 = CF

    //----- hi(a[0~3] * b[4]) -----
    umulh   x6, x14 , x24
    umulh   x7, x15 , x24
    umulh   x8, x16 , x24
    umulh   x9, x17 , x24

    ldr     x24, [x2, x20]          // b[i]
    mul     x21, x4 , x27           // t[0] * k0
    str     x21, [x22], #8          // t[0] * k0 push

    adds    x28, x28, x6
    adcs    x25, x25, x7
    adcs    x26, x26, x8
    adc     x23, x23, x9           // It doesn't overflow. Here x23 is the carry.

    //----- lo(n[1~3] * t[0]*k0) -----
    mul     x7, x11, x21
    mul     x8, x12, x21
    mul     x9, x13, x21

    subs    xzr, x27, #1            // Take the symbol of x19-1

    adcs    x27, x28, x7
    adcs    x28, x25, x8
    adcs    x25, x26, x9
    adcs    x26, x23, x0
    adc     x0 , xzr, xzr           // x0 = CF

    //----- hi(n[0~3] * t[0]*k0) -----
    umulh   x6, x10, x21
    umulh   x7, x11, x21
    umulh   x8, x12, x21
    umulh   x9, x13, x21

    adds    x27, x27, x6
    adcs    x28, x28, x7
    adcs    x25, x25, x8
    adcs    x26, x26, x9
    cbnz    x20, .LReduceMul4x

    adc     x0 , x0 , xzr
    ldp     x6, x7, [x22, #8*4]   // t[4~7]
    ldp     x8, x9, [x22, #8*6]

    ldp     x14 , x15 , [x1 , #8*0]   // a[4~7]
    ldp     x16 , x17 , [x1 , #8*2]

    add     x1 , x1 , #8*4
    adds    x27, x27, x6
    adcs    x28, x28, x7
    adcs    x25, x25, x8
    adcs    x26, x26, x9

    ldr     x21, [sp]               // Re-extract [0]*k0
    ldp     x10, x11, [x3, #8*0]    // n[4~7]
    ldp     x12, x13, [x3, #8*2]
    add     x3 , x3 , #8*4          // n is offset by 4 each time.

.align  4
.LLastMul4x:
    //----- lo(a[4~7] * b[4]) -----
    adc     x0 , x0 , xzr
    add     x20, x20, #8            // x20 += 8, cyclic increment
    and     x20, x20, #31           // When x28 increases to 32, x20 = 0, and data is grouped in sets of four.

    //----- lo(a[4~7] * b[4]) -----
    mul     x6, x14 , x24
    mul     x7, x15 , x24
    mul     x8, x16 , x24
    mul     x9, x17 , x24

    adds    x27, x27, x6
    adcs    x28, x28, x7
    adcs    x25, x25, x8
    adcs    x26, x26, x9
    adc     x23, xzr, xzr           // x23 = CF

    //----- hi(a[4~7] * b[4]) -----
    umulh   x6, x14 , x24
    umulh   x7, x15 , x24
    umulh   x8, x16 , x24
    umulh   x9, x17 , x24

    ldr     x24, [x2, x20]          // b[i]

    adds    x28, x28, x6
    adcs    x25, x25, x7
    adcs    x26, x26, x8
    adc     x23, x23, x9           // It doesn't overflow. Here x23 is the carry.

    //----- lo(n[4~7] * t[0]*k0) -----
    mul     x6, x10, x21
    mul     x7, x11, x21
    mul     x8, x12, x21
    mul     x9, x13, x21

    adds    x27, x27, x6
    adcs    x28, x28, x7
    adcs    x25, x25, x8
    adcs    x26, x26, x9
    adcs    x23, x23, x0

    //----- hi(n[4~7] * t[0]*k0) -----
    umulh   x6, x10, x21
    umulh   x7, x11, x21
    umulh   x8, x12, x21
    umulh   x9, x13, x21

    ldr     x21, [sp, x20]          // t[0]*k0
    adc     x0 , xzr, xzr           // x0 = CF, record carry
    str     x27, [x22], #8          // s[i] the calculation is complete, and write the result, x22 += 8

    adds    x27, x28, x6
    adcs    x28, x25, x7
    adcs    x25, x26, x8
    adcs    x26, x23, x9

    sub     x6, x19, x1            // Indicates whether the loop ends.

    cbnz    x20, .LLastMul4x

    sub     x7, x3 , x5            // x7 = &n[0]
    adc     x0 , x0 , xzr
    cbz     x6, .LBreakMul4x

    ldp     x6, x7, [x22, #8*4]   // remove 4 t
    ldp     x8, x9, [x22, #8*6]

    ldp     x14 , x15 , [x1 , #8*0]   // remove 4 a
    ldp     x16 , x17 , [x1 , #8*2]

    add     x1 , x1 , #8*4

    adds    x27, x27, x6
    adcs    x28, x28, x7
    adcs    x25, x25, x8
    adcs    x26, x26, x9

    ldp     x10, x11, [x3, #8*0]    // remove 4 n
    ldp     x12, x13, [x3, #8*2]
    add     x3 , x3 , #8*4          // n Subscript one-time offset 4, CF clear to zero
    b       .LLastMul4x

.align  4
.LBreakMul4x:
    ldp     x8, x9, [x29, #96]    // r&b[size] Pop-Stack
    add     x2 , x2 , #8*4          // b subscript is offset once by 4 each time, &b[4], &b[8]......
    sub     x1 , x1 , x5            // x1 = &a[0]

    adds    x27, x27, x30
    adcs    x28, x28, xzr
    stp     x27, x28, [x22, #8*0]   // x27, x20 After the calculation is complete, Push-stack storage
    ldp     x27, x28, [sp , #8*4]   // t[0], t[1]

    adcs    x25, x25, xzr
    adcs    x26, x26, xzr
    stp     x25, x26, [x22, #8*2]   // x25, x22 After the calculation is complete, Push-stack storage
    ldp     x25, x26, [sp , #8*6]   // t[2], t[3]

    adc     x30, x0 , xzr
    cmp     x2 , x9                // Indicates whether the outer loop ends.

    ldp     x10, x11, [x7, #8*0]   // n[0~3]
    ldp     x12, x13, [x7, #8*2]
    add     x3 , x7, #8*4          // x11 is assigned &n[0] on line 1167
    b.eq    .LEndMul4x

    ldr     x24, [x2]               // x24 = b[4i], Lowest block of the current b data block
    ldp     x14 , x15 , [x1, #8*0]    // a[0~3]
    ldp     x16 , x17 , [x1, #8*2]
    adds    x1 , x1 , #8*4          // a subscript is offset once by 4 each time, CF = 0
    mov     x0 , xzr
    mov     x22, sp
    b       .LReduceMul4x

.align  4
.LEndMul4x:
    mov     x0 , x8                // x0 = &r[0]
    mov     x19, x8                // backup, x19 = &r[0]
    subs    x6, x27, x10           // t[0] - n[0], modify CF
    sbcs    x7, x28, x11           // t[1] - n[1] - CF
    add     x22, sp , #8*8          // x22 = &S[8]
    sub     x20, x5 , #8*4          // x20 = (size - 4)*8

// S - N, x22 = &S[8], x3 = &n[0]
.LSubMul4x:
    sbcs    x8, x25, x12
    sbcs    x9, x26, x13
    ldp     x10, x11, [x3]
    ldp     x12, x13, [x3, #8*2]
    add     x3 , x3 , #8*4

    ldp     x27, x28, [x22]
    ldp     x25, x26, [x22, #8*2]
    add     x22, x22, #8*4

    sub     x20, x20, #8*4

    stp     x6, x7, [x0]
    stp     x8, x9, [x0 , #8*2]
    add     x0 , x0 , #8*4

    sbcs    x6, x27, x10
    sbcs    x7, x28, x11

    cbnz    x20, .LSubMul4x

    sbcs    x8, x25, x12
    mov     x22, sp
    add     x1 , sp , #8*4          // The size of the SP space is size + 4., x1 = sp + 4

    ldp     x14 , x15 , [x19]         // x14~x17 = r[0~3]
    ldp     x16 , x17 , [x19, #8*2]

    sbcs    x9, x26, x13

    stp     x6, x7, [x0]
    stp     x8, x9, [x0 , #8*2]

    ldp     x27, x28, [x1 , #8*0]   // x27~22 = S[4~7]
    ldp     x25, x26, [x1 , #8*2]

    sbcs    xzr, x30, xzr           // CF = x30 - CF, x30 recorded the previous carry

    sub     x20, x5 , #8*4

.LCopyMul4x:
    sub     x20, x20, #8*4
    stp     xzr, xzr, [x22, #8*0]
    stp     xzr, xzr, [x22, #8*2]
    csel    x6, x27, x14, lo        // x6 = (CF == 1) ? x27 : x14
    csel    x7, x28, x15, lo
    ldp     x14 , x15 , [x19, #8*4]   // x14 = r[4], x15 = r[5]
    ldp     x27, x28, [x1 , #8*4]

    csel    x8, x25, x16, lo
    csel    x9, x26, x17, lo
    ldp     x16 , x17 , [x19, #8*6]   // x16 = r[6], x17 = r[7]
    ldp     x25, x26, [x1 , #8*6]

    add     x1 , x1 , #8*4
    stp     x6, x7, [x19]         // r[0~3] =
    stp     x8, x9, [x19, #8*2]

    add     x19, x19, #8*4
    add     x22, x22, #8*4
    cbnz    x20, .LCopyMul4x

    csel    x6, x27, x14, lo
    csel    x7, x28, x15, lo
    csel    x8, x25, x16, lo
    csel    x9, x26, x17, lo
    stp     xzr, xzr, [x22, #8*0]
    stp     xzr, xzr, [x22, #8*2]
    stp     xzr, xzr, [x22, #8*4]
    stp     x6, x7, [x19, #8*0]
    stp     x8, x9, [x19, #8*2]

    b       .BnMontMul4xEnd

.align  4
.LEndCondMul4x:
    adc     x0 , x0 , xzr
    ldr     x1 , [x29, #96]         // r Pop-Stack, x1 = &r[0]

    subs    x14 , x27, x10
    sbcs    x15 , x28, x11
    sbcs    x16 , x25, x12
    sbcs    x17 , x26, x13
    stp     xzr, xzr, [sp, #8*0]
    stp     xzr, xzr, [sp, #8*2]
    stp     xzr, xzr, [sp, #8*4]
    stp     xzr, xzr, [sp, #8*6]
    sbcs    xzr, x0 , xzr           // CF = x0 - CF, Determine whether to borrow

    csel    x14 , x27, x14 , lo
    csel    x15 , x28, x15 , lo
    csel    x16 , x25, x16 , lo
    csel    x17 , x26, x17 , lo
    stp     x14 , x15 , [x1, #8*0]
    stp     x16 , x17 , [x1, #8*2]

.BnMontMul4xEnd:
    ldr     x30, [x29, #8]          // Value Pop-Stack in x30 (address of next instruction)
    ldp     x27, x28, [x29, #16]
    ldp     x25, x26, [x29, #32]
    ldp     x23, x24, [x29, #48]
    ldp     x21, x22, [x29, #64]
    ldp     x19, x20, [x29, #80]
    mov     sp , x29
    ldr     x29, [sp], #128
    ret
.size   MontMul4, .-MontMul4
