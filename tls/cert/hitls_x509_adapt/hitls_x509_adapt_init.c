/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */
#include <stddef.h>
#include <stdint.h>
#include "hitls_cert_type.h"
#include "hitls_type.h"

int32_t HITLS_CertMethodInit(void)
{
    return 0;
}

void HITLS_X509_Adapt_StoreFree(HITLS_CERT_Store *store)
{
    (void)store;
}

HITLS_CERT_Store *HITLS_X509_Adapt_StoreNew(void)
{
    return NULL;
}

void HITLS_X509_Adapt_CertFree(HITLS_CERT_X509 *cert)
{
    (void)cert;
}

HITLS_CERT_Key *HITLS_X509_Adapt_KeyParse(HITLS_Config *config, const uint8_t *buf, uint32_t len,
    HITLS_ParseType type, HITLS_ParseFormat format)
{
    (void)config;
    (void)buf;
    (void)len;
    (void)type;
    (void)format;
    return NULL;
}