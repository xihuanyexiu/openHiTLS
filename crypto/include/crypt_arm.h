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

#ifndef CRYPT_ARM_H
#define CRYPT_ARM_H

#ifndef CRYPT_VAL
#define CRYPT_VAL               16
#endif
#ifndef CRYPT_VAL2
#define CRYPT_VAL2              26
#endif
#if defined(__arm__) || defined (__arm)
#define CRYPT_CAP               CRYPT_VAL
#define CRYPT_CE                CRYPT_VAL2
#define CRYPT_ARM_NEON          (1 << 12)
#define CRYPT_ARM_AES           (1 << 0)
#define CRYPT_ARM_PMULL         (1 << 1)
#define CRYPT_ARM_SHA1          (1 << 2)
#define CRYPT_ARM_SHA256        (1 << 3)
#elif defined(__aarch64__)
#define CRYPT_CAP               CRYPT_VAL
#define CRYPT_CE                CRYPT_VAL
#define CRYPT_ARM_NEON          (1 << 1)
#define CRYPT_ARM_AES           (1 << 3)
#define CRYPT_ARM_PMULL         (1 << 4)
#define CRYPT_ARM_SHA1          (1 << 5)
#define CRYPT_ARM_SHA256        (1 << 6)
#define CRYPT_ARM_SM3           (1 << 18)
#define CRYPT_ARM_SM4           (1 << 19)
#define CRYPT_ARM_SHA512        (1 << 21)
#endif

#ifndef __ASSEMBLER__
extern uint32_t g_cryptArmCpuInfo;
#else
#  ifdef HITLS_AARCH64_PACIASP
#   define AARCH64_PACIASP hint #25
#   define AARCH64_AUTIASP hint #29
#   define PROPERTY_AARCH64_PAC 2
#  else
#   define AARCH64_PACIASP
#   define AARCH64_AUTIASP
#   define PROPERTY_AARCH64_PAC 0
#  endif

#  ifdef HITLS_AARCH64_BTI
#   define AARCH64_BTIC hint #34
#   define PROPERTY_AARCH64_BTI 1
#  else
#   define AARCH64_BTIC
#   define PROPERTY_AARCH64_BTI 0
#  endif

#  if PROPERTY_AARCH64_PAC != 0 || PROPERTY_AARCH64_BTI != 0
#   if defined(__ILP32__)
      .pushsection .note.gnu.property, "a";
      .p2align 2;
      .word 4;
      .word 12;
      .word 5;
      .asciz "GNU";
      .word 0xc0000000;
      .word 4;
      .word (PROPERTY_AARCH64_PAC | PROPERTY_AARCH64_BTI);
      .p2align 2;
      .popsection;
#   else
      .pushsection .note.gnu.property, "a";
      .p2align 3;
      .word 4;
      .word 16;
      .word 5;
      .asciz "GNU";
      .word 0xc0000000;
      .word 4;
      .word (PROPERTY_AARCH64_PAC | PROPERTY_AARCH64_BTI);
      .word 0;
      .popsection;
#   endif
#  endif

#endif

#endif