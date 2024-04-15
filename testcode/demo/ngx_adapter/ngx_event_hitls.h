/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "tls/hitls_type.h"
#include "x509/hitls_x509.h"
#include "ngx_event_ssl.h"
#ifdef NGX_HITLS_SDF
#include "hitls_sdf/cert.h"
#endif

#define ngx_ssl_version() OPENHITLS_VERSION_S

#define ngx_ssl_verify_error_optional(n) 0

#define X509_V_OK 0

typedef HITLS_Config ngx_ssl_ctx_t;
typedef HITLS_Ctx ngx_ssl_conn_t;
typedef HITLS_X509_Cert ngx_x509_t;
typedef HITLS_Session ngx_ssl_session_t;

#define ngx_ssl_error ngx_log_error
