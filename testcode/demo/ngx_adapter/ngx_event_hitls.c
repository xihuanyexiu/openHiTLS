/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "ngx_event_hitls.h"
#include "bsl/bsl_err.h"
#include "bsl/bsl_uio.h"
#include "bsl/bsl_sal.h"
#include "crypto/crypt_algid.h"
#include "crypto/crypt_eal_rand.h"
#include "tls/hitls.h"
#include "tls/hitls_cert.h"
#include "tls/hitls_cert_init.h"
#include "tls/hitls_config.h"
#include "tls/hitls_crypt_init.h"
#include "tls/hitls_error.h"
#include "tls/hitls_session.h"
#include "cert_mgr.h"
#include "eal_pkey_local.h"
#include "crypt_eal_pkey.h"
#include "ngx_log.h"
#include "ngx_event.h"
#ifdef NGX_HITLS_SDF
#include "hitls_sdf/lib_load.h"
#include "hitls_sdf/cert.h"
#include "hitls_sdf/crypto_user_method.h"
#include "hitls_sdf/crypto.h"
#include "hitls_crypt_reg.h"
#endif

#define NGX_ERROR_IF_NULL(exp, log, tag) if ((exp) == NULL) { ngx_ssl_error(NGX_LOG_ALERT, (log), 0, tag); return NGX_ERROR;}
#define NGX_ERROR_IF_FAIL(exp, log, tag) if ((exp)) { ngx_ssl_error(NGX_LOG_ALERT, (log), 0, tag); return NGX_ERROR;}
#define GOTO_ERR_IF_FAIL(exp, log, tag) if ((exp)) { ngx_ssl_error(NGX_LOG_ALERT, (log), 0, tag); goto ERR;}

typedef struct {
    ngx_uint_t engine;
} ngx_hitls_conf_t;

static void *ngx_hitls_create_conf(ngx_cycle_t *cycle)
{
    ngx_hitls_conf_t *hitls_cf;
    hitls_cf = ngx_pcalloc(cycle->pool, sizeof(ngx_hitls_conf_t));
    if (hitls_cf == NULL)
        return NULL;
    return hitls_cf;
}

static ngx_core_module_t ngx_hitls_module_ctx = {
    ngx_string("hitls"),
    ngx_hitls_create_conf,
    NULL
};

ngx_module_t ngx_hitls_module = {
    NGX_MODULE_V1,
    &ngx_hitls_module_ctx,
    NULL,
    NGX_CORE_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};

static void ngx_ssl_clear_error(ngx_log_t *log)
{
    BSL_ERR_ClearError();
}

ngx_int_t ngx_ssl_shutdown(ngx_connection_t *c) 
{
    if (c->ssl->subject_dn.data) {
        BSL_SAL_FREE(c->ssl->subject_dn.data);
    }
    if (c->ssl->issuer_dn.data) {
        BSL_SAL_FREE(c->ssl->issuer_dn.data);
    }
    int ret = HITLS_Close(c->ssl->connection);
    BSL_UIO_Free(HITLS_GetUio(c->ssl->connection));
    HITLS_Free(c->ssl->connection);
    c->ssl->connection = NULL;
    return ret;
}

long ngx_ssl_get_verify_result(const ngx_ssl_conn_t *ssl) 
{
    fprintf(stderr, "[WARN] ngx_ssl_get_verify_result not implemented.\n");
    return 0;
}

ngx_int_t ngx_ssl_ocsp_get_status(ngx_connection_t *c, const char **s) 
{
    fprintf(stderr, "[WARN] OCSP Not supported.\n");
    return 0;
}

ngx_ssl_session_t *ngx_ssl_get0_session(ngx_connection_t *c) 
{
    return HITLS_GetSession(c->ssl->connection);
}

void ngx_ssl_remove_cached_session(ngx_ssl_ctx_t *ssl, ngx_ssl_session_t *sess)
{
    fprintf(stderr, "[WARN] ngx_ssl_remove_cached_session not implemented.\n");
}

const char *ngx_x509_verify_cert_error_string(long error_code)
{
    return BSL_ERR_GetString(error_code);
}

ngx_x509_t *ngx_ssl_get_peer_certificate(const ngx_ssl_conn_t *ssl)
{
    return HITLS_GetPeerCertificate(ssl);
}

void ngx_x509_free(ngx_x509_t *x509)
{
    HITLS_X509_FreeCert(x509);
}

ngx_int_t ngx_ssl_create_connection(ngx_ssl_t *ssl, ngx_connection_t *c,
    ngx_uint_t flags)
{
    ngx_ssl_connection_t *sc;
    BSL_UIO *uio = NULL;

    // We will erenter here if TLS handshake receive recoverable exception like IO busy.
    // We won't initialize SSL context again if it is already initialized.
    if (c->ssl != 0) {
        return NGX_OK;
    }

    sc = ngx_pcalloc(c->pool, sizeof(ngx_ssl_connection_t));
    if (sc == NULL) {
        return NGX_ERROR;
    }

    sc->buffer = ((flags & NGX_SSL_BUFFER) != 0);
    sc->buffer_size = ssl->buffer_size;

    sc->session_ctx = ssl->ctx;

    //TODO SSL_READ_EARLY_DATA_SUCCESS

    NGX_ERROR_IF_NULL(
            sc->connection = HITLS_New((HITLS_Config *) ssl->ctx), c->log, "HITLS_New() failed");
    NGX_ERROR_IF_NULL(
            uio = BSL_UIO_New(BSL_UIO_TcpMethod()), c->log, "BSL_UIO_New() failed");
    GOTO_ERR_IF_FAIL(
            BSL_UIO_Ctrl(uio, BSL_UIO_SET_FD, sizeof(c->fd), &c->fd), c->log, "BSL_UIO_Ctrl(BSL_UIO_SET_FD) failed");
    GOTO_ERR_IF_FAIL(
            HITLS_SetUio(sc->connection, uio), c->log, "BSL_UIO_Ctrl(BSL_UIO_SET_FD) failed");

    if (flags & NGX_SSL_CLIENT) {
        sc->is_client = 1;
    }

    c->ssl = sc;
    return NGX_OK;

ERR:
    if (sc->connection) {
        HITLS_Free(sc->connection);
    }
    if (sc) {
        ngx_pfree(c->pool, sc);
    }
    if (uio) {
        BSL_UIO_Free(uio);
    }
    return NGX_ERROR;
}

ngx_int_t ngx_ssl_handshake(ngx_connection_t *c)
{
    int ret;
    
    if (c->ssl->is_client) {
        ret = HITLS_Connect((HITLS_Ctx *) c->ssl->connection);
    } else {
        ret = HITLS_Accept((HITLS_Ctx *) c->ssl->connection);
    }
    if (ret != HITLS_SUCCESS) {
        //TODO More error handling 
        if (ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY || ret == HITLS_REC_NORMAL_IO_BUSY) {
            return NGX_AGAIN;
        }
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "HITLS_Accept failed");
        return NGX_ERROR;
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    c->recv = ngx_ssl_recv;
    c->send = ngx_ssl_write;
    c->recv_chain = ngx_ssl_recv_chain;
    c->send_chain = ngx_ssl_send_chain;

    c->read->ready = 1;
    c->write->ready = 1;

    //TODO validate OCSP

    c->ssl->handshaked = 1;
    return NGX_OK;
}

static ngx_int_t ngx_ssl_handle_recv(ngx_connection_t *c, int n, int sslerr)
{
    if (sslerr == HITLS_SUCCESS && n > 0) {

        if (c->ssl->saved_write_handler) {

            c->write->handler = c->ssl->saved_write_handler;
            c->ssl->saved_write_handler = NULL;
            c->write->ready = 1;

            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                return NGX_ERROR;
            }

            ngx_post_event(c->write, &ngx_posted_events);
        }

        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);

    if (sslerr == HITLS_REC_NORMAL_RECV_BUF_EMPTY) {

        if (c->ssl->saved_write_handler) {

            c->write->handler = c->ssl->saved_write_handler;
            c->ssl->saved_write_handler = NULL;
            c->write->ready = 1;

            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                return NGX_ERROR;
            }

            ngx_post_event(c->write, &ngx_posted_events);
        }

        c->read->ready = 0;
        return NGX_AGAIN;
    }

    if (sslerr == HITLS_WANT_WRITE) {

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL_read: want write");

        c->write->ready = 0;

        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        /*
         * we do not set the timer because there is already the read event timer
         */

        if (c->ssl->saved_write_handler == NULL) {
            c->ssl->saved_write_handler = c->write->handler;
            c->write->handler = ngx_ssl_write_handler;
        }

        return NGX_AGAIN;
    }

    c->ssl->no_wait_shutdown = 1;
    c->ssl->no_send_shutdown = 1;

    ngx_ssl_error(NGX_LOG_ERR, c->log, 0, "SSL_read() failed");

    return NGX_ERROR;
}

ssize_t ngx_ssl_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    unsigned int n = 0;

    if (c->ssl->last == NGX_ERROR) {
        c->read->ready = 0;
        c->read->error = 1;
        return NGX_ERROR;
    }

    if (c->ssl->last == NGX_DONE) {
        c->read->ready = 0;
        c->read->eof = 1;
        return 0;
    }

    int bytes = 0;

    ngx_ssl_clear_error(c->log);

    /*
     * SSL_read() may return data in parts, so try to read
     * until SSL_read() would return no data
     */

    for ( ;; ) {

        int ret = HITLS_Read(c->ssl->connection, buf, size, &n);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_read: %d", n);

        if (n > 0) {
            bytes += n;
        }

        c->ssl->last = ngx_ssl_handle_recv(c, n, ret);

        if (c->ssl->last == NGX_OK) {

            size -= n;

            if (size == 0) {
                c->read->ready = 1;

                if (c->read->available >= 0) {
                    c->read->available -= bytes;

                    /*
                     * there can be data buffered at SSL layer,
                     * so we post an event to continue reading on the next
                     * iteration of the event loop
                     */

                    if (c->read->available < 0) {
                        c->read->available = 0;
                        c->read->ready = 0;

                        if (c->read->posted) {
                            ngx_delete_posted_event(c->read);
                        }

                        ngx_post_event(c->read, &ngx_posted_next_events);
                    }

                    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                                   "SSL_read: avail:%d", c->read->available);

                } else {

#if (NGX_HAVE_FIONREAD)

                    if (ngx_socket_nread(c->fd, &c->read->available) == -1) {
                        c->read->ready = 0;
                        c->read->error = 1;
                        ngx_connection_error(c, ngx_socket_errno,
                                             ngx_socket_nread_n " failed");
                        return NGX_ERROR;
                    }

                    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                                   "SSL_read: avail:%d", c->read->available);

#endif
                }

                return bytes;
            }

            buf += n;

            continue;
        }

        if (bytes) {
            if (c->ssl->last != NGX_AGAIN) {
                c->read->ready = 1;
            }

            return bytes;
        }

        switch (c->ssl->last) {

        case NGX_DONE:
            c->read->ready = 0;
            c->read->eof = 1;
            return 0;

        case NGX_ERROR:
            c->read->ready = 0;
            c->read->error = 1;

            /* fall through */

        case NGX_AGAIN:
            return c->ssl->last;
        }
    }

}

ssize_t ngx_ssl_write(ngx_connection_t *c, u_char *data, size_t size)
{
    int        n, sslerr;

    ngx_ssl_clear_error(c->log);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL to write: %uz", size);

    n = HITLS_Write(c->ssl->connection, data, size);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_write: %d", n);

    if (n == HITLS_SUCCESS) {

        if (c->ssl->saved_read_handler) {

            c->read->handler = c->ssl->saved_read_handler;
            c->ssl->saved_read_handler = NULL;
            c->read->ready = 1;

            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                return NGX_ERROR;
            }

            ngx_post_event(c->read, &ngx_posted_events);
        }

        c->sent += size;

        return size;
    }

    sslerr = n;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);

    if (sslerr == HITLS_WANT_WRITE) {

        if (c->ssl->saved_read_handler) {

            c->read->handler = c->ssl->saved_read_handler;
            c->ssl->saved_read_handler = NULL;
            c->read->ready = 1;

            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                return NGX_ERROR;
            }

            ngx_post_event(c->read, &ngx_posted_events);
        }

        c->write->ready = 0;
        return NGX_AGAIN;
    }

    if (sslerr == HITLS_WANT_READ) {

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL_write: want read");

        c->read->ready = 0;

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        /*
         * we do not set the timer because there is already
         * the write event timer
         */

        if (c->ssl->saved_read_handler == NULL) {
            c->ssl->saved_read_handler = c->read->handler;
            c->read->handler = ngx_ssl_read_handler;
        }

        return NGX_AGAIN;
    }

    c->ssl->no_wait_shutdown = 1;
    c->ssl->no_send_shutdown = 1;
    c->write->error = 1;

    ngx_ssl_error(NGX_LOG_ERR, c->log, 0, "SSL_write() failed");

    return NGX_ERROR;
}

ngx_int_t
ngx_ssl_check_host(ngx_connection_t *c, ngx_str_t *name)
{
    ngx_ssl_error(NGX_LOG_ERR, c->log, 0, "ngx_ssl_check_host not implemented");
    //TODO verify cert CN
    return NGX_OK;
}

ngx_int_t
ngx_ssl_connection_certificate(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *cert, ngx_str_t *key, ngx_array_t *passwords)
{
    ngx_ssl_error(NGX_LOG_ERR, c->log, 0, "ngx_ssl_connection_certificate not implemented");
    return NGX_ERROR;
}
 
ngx_ssl_session_t *ngx_d2i_ssl_session(ngx_ssl_session_t **a, const unsigned char **pp, long len)
{
    fprintf(stderr, "ngx_d2i_ssl_session not implemented.\n");
    return 0;
}

ngx_int_t
ngx_ssl_set_session(ngx_connection_t *c, ngx_ssl_session_t *session)
{
    if (session) {
        NGX_ERROR_IF_FAIL(
                HITLS_SetSession(c->ssl->connection, session), c->log, "HITLS_SetSession() failed");
    }

    return NGX_OK;
}

void ngx_ssl_free_session(ngx_ssl_session_t *session)
{
    HITLS_SESS_Free(session);
}

int ngx_i2d_ssl_session(ngx_ssl_session_t *in, unsigned char **pp)
{
    fprintf(stderr, "ngx_i2d_ssl_session not implemented.\n");
    return 0;
}

ngx_ssl_session_t *ngx_ssl_get_session(ngx_connection_t *c)
{
    return HITLS_GetDupSession(c->ssl->connection);
}

ngx_int_t ngx_ssl_ocsp_cache_init(ngx_shm_zone_t *shm_zone, void *data)
{
    fprintf(stderr, "ngx_ssl_ocsp_cache_init not implemented.\n");
    return NGX_ERROR;
}

ngx_int_t
ngx_ssl_session_cache(ngx_ssl_t *ssl, ngx_str_t *sess_ctx,
    ngx_array_t *certificates, ssize_t builtin_session_cache,
    ngx_shm_zone_t *shm_zone, time_t timeout)
{
    HITLS_Config *config = (HITLS_Config *) ssl->ctx;
    if (builtin_session_cache < 0 && builtin_session_cache != NGX_SSL_NONE_SCACHE) {
        return NGX_ERROR;
    }
    if (HITLS_CFG_SetSessionTimeout(config, timeout) != HITLS_SUCCESS) {
        return NGX_ERROR;
    }
    if (builtin_session_cache == NGX_SSL_NONE_SCACHE) {
        if (HITLS_CFG_SetSessionCacheMode(config, HITLS_SESS_CACHE_NO) != HITLS_SUCCESS) {
            return NGX_ERROR;
        }
        return NGX_OK;
    }
    if (HITLS_CFG_SetSessionCacheMode(config, HITLS_SESS_CACHE_SERVER) != HITLS_SUCCESS) {
        return NGX_ERROR;
    }
    if (HITLS_CFG_SetSessionCacheSize(config, builtin_session_cache) != HITLS_SUCCESS) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t ngx_ssl_session_cache_init(ngx_shm_zone_t *shm_zone, void *data)
{
    fprintf(stderr, "ngx_ssl_session_cache_init not implemented.\n");
    return NGX_ERROR;
}

ngx_int_t
ngx_ssl_stapling_resolver(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_resolver_t *resolver, ngx_msec_t resolver_timeout)
{
    return NGX_OK;
}

ngx_int_t
ngx_ssl_ocsp_resolver(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_resolver_t *resolver, ngx_msec_t resolver_timeout)
{
    return NGX_OK;
}

#ifdef NGX_HITLS_SDF
extern HITLS_CRYPT_BaseMethod g_cryptBaseMethod;
extern HITLS_CERT_MgrMethod g_certMgrMethod;
#endif

ngx_int_t
ngx_ssl_create(ngx_ssl_t *ssl, ngx_uint_t protocols, void *data)
{
    BSL_ERR_Init();
    HITLS_CertMethodInit();
    HITLS_CryptMethodInit();
    fprintf(stderr, "CRYPT_EAL_RandInit start.\n");
    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, 0, 0, 0, 0);
    fprintf(stderr, "CRYPT_EAL_RandInit complete.\n");

#ifdef NGX_HITLS_SDF
    if (ssl->sdf) {
        if (HITLS_SDF_lib_load((char *) ssl->sdf_lib_path.data)) {
            fprintf(stderr, "SDF lib load failed.\n");
            return NGX_ERROR;
        }
        if (HITLS_SDF_init_global_session()) {
            fprintf(stderr, "SDF init session failed.\n");
            return NGX_ERROR;
        }
        g_cryptBaseMethod.randBytes = HITLS_SDF_RAND_rand_bytes;
        g_certMgrMethod.keyCtrl = (CERT_KeyCtrlCallBack) HITLS_SDF_CERT_KeyCtrl;
        g_certMgrMethod.checkPrivateKey = (CERT_CheckPrivateKeyCallBack) HITLS_SDF_CERT_CheckPrivateKey;
        g_certMgrMethod.keyDup = (CERT_UserKeyDupCallBack) HITLS_SDF_CERT_KeyDup;
        g_certMgrMethod.keyFree = (CERT_KeyFreeCallBack) HITLS_SDF_CERT_KeyFree;

        CRYPT_EAL_MdRegMethod(CRYPT_MD_SM3, HITLS_SDF_GetMdUserMethod());
        CRYPT_EAL_MacRegMethod(CRYPT_MAC_HMAC_SM3, HITLS_SDF_GetMacUserMethod());
        CRYPT_EAL_CipherRegMethod(CRYPT_CIPHER_SM4_CBC, HITLS_SDF_GetCipherUserMethod());
        CRYPT_EAL_PkeyRegMethod(CRYPT_PKEY_SM2, HITLS_SDF_GetPKeyUserMethod());
    }
#endif

    ssl->protocols = protocols;
    if (protocols == NGX_SSL_TLCP) {
        ssl->ctx = HITLS_CFG_NewTLCPConfig();
    } else {
        ssl->ctx = HITLS_CFG_NewTLS12Config();
    }
    HITLS_CFG_SetCloseCheckKeyUsage(ssl->ctx, false);

    //nginx close extendkey
    HITLS_CFG_SetExtenedMasterSecretSupport(ssl->ctx, false);

    return NGX_OK;
}

void ngx_ssl_cleanup_ctx(void *data)
{
    ngx_ssl_t  *ssl = data;

    HITLS_CFG_FreeConfig(ssl->ctx);
}

ngx_int_t
ngx_ssl_ciphers(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *ciphers,
    ngx_uint_t prefer_server_ciphers)
{
    if (prefer_server_ciphers) {
        HITLS_CFG_SetCipherServerPreference(ssl->ctx, true);
    }
    return NGX_OK;
}

ngx_array_t *
ngx_ssl_preserve_passwords(ngx_conf_t *cf, ngx_array_t *passwords)
{
    static ngx_array_t empty_passwords;
    fprintf(stderr, "ngx_ssl_preserve_passwords not implemented.\n");
    return &empty_passwords;
}

static ngx_x509_t *LoadCert(ngx_str_t *file, HITLS_Config *config)
{
    char file_content[4096] = {0};
    ngx_x509_t *cert;

    FILE *f = fopen((const char *) file->data, "r");
    if (f == NULL) {
        fprintf(stderr, "fopen Error\n");
        return NULL;
    }

    for (int i=0; i < 4096; i++) {
        int c = fgetc(f);
        if (c != EOF) {
            file_content[i] = c;
        } else {
            break;
        }
    }

    cert = HITLS_CFG_ParseCert(config, file_content, 4096, TLS_PARSE_TYPE_BUFF, TLS_PARSE_FORMAT_PEM);

    (void)fclose(f);
    return cert;
}

static int sign_cert_loaded = 0;
static int setTlcpCertificateAndKey(ngx_ssl_t *ssl, ngx_x509_t *cert_x509, HITLS_CERT_Key *key)
{
    int ret = 0;

    NGX_ERROR_IF_FAIL(
            HITLS_CFG_SetTlcpCertificate(ssl->ctx, cert_x509, 1, sign_cert_loaded), ssl->log, "HITLS_CFG_SetTlcpCertificate failed.");

    ret = HITLS_CFG_SetTlcpPrivateKey(ssl->ctx, key, 1, sign_cert_loaded);
    if (ret != HITLS_SUCCESS) {
        if (ret == HITLS_CERT_ERR_CHECK_CERT_AND_KEY) {
            ngx_log_error(NGX_LOG_ERR, ssl->log, 0, "Tlcp certificate and key checked failed");
        } else {
            ngx_log_error(NGX_LOG_ERR, ssl->log, 0, "HITLS_CFG_SetTlcpPrivateKey failed 0x%x.", ret);
        }
        return NGX_ERROR;
    }
    sign_cert_loaded = 1;
    return NGX_OK;
}

static int setTlsCertificateAndKey(ngx_ssl_t *ssl, ngx_x509_t *cert_x509, HITLS_CERT_Key *key)
{
    int ret = 0;
    if (HITLS_CFG_SetCertificate(ssl->ctx, cert_x509, 1) != HITLS_SUCCESS) {
        return NGX_ERROR;
    }
    if ((ret = HITLS_CFG_SetPrivateKey(ssl->ctx, key, 1)) != HITLS_SUCCESS) {
        if (ret == HITLS_CERT_ERR_CHECK_CERT_AND_KEY) {
            ngx_log_error(NGX_LOG_ERR, ssl->log, 0, "TLS Certificate and Key check failed.");
        } else {
            ngx_log_error(NGX_LOG_ERR, ssl->log, 0, "HITLS_CFG_SetPrivateKey failed 0x%x.", ret);
        }
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t
ngx_ssl_certificates(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_array_t *certs,
    ngx_array_t *keys, ngx_array_t *passwords)
{
    ngx_str_t   *cert, *key;
    ngx_uint_t   i;

    cert = certs->elts;
    key = keys->elts;

    if (ssl->protocols == NGX_SSL_TLCP && certs->nelts != 2) {
        if (certs->nelts == 1) {
            ngx_log_error(NGX_LOG_ERR, ssl->log, 0, 
                "Missing the ENC certificate for TLCP.");
        } else {
            ngx_log_error(NGX_LOG_ERR, ssl->log, 0, 
                "Invalid number of certificates for TLCP: %d.", certs->nelts);
        }
    }
    for (i = 0; i < certs->nelts; i++) {

        if (ngx_ssl_certificate(cf, ssl, &cert[i], &key[i], passwords)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

ngx_int_t
ngx_ssl_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *cert,
    ngx_str_t *key, ngx_array_t *passwords)
{
    int ret = 0;
    ngx_x509_t *cert_x509 = NULL;
    HITLS_CERT_Key *cert_key = 0;
    int success = 0;

    NGX_ERROR_IF_NULL(
            cert_x509 = LoadCert(cert, ssl->ctx), ssl->log, "LoadCert failed.");

#ifdef NGX_HITLS_SDF
    if (ssl->sdf) {
        if (!sign_cert_loaded) {
            fprintf(stderr, "Load sdf key %s.\n", key->data);
            NGX_ERROR_IF_FAIL(
                    HITLS_CFG_SetTlcpCertificate(ssl->ctx, cert_x509, 1, sign_cert_loaded), ssl->log, "HITLS_CFG_SetTlcpCertificate failed.");

            char *pass = (char *)((ngx_str_t *) passwords->elts)->data;
            unsigned int passLen = ((ngx_str_t *) passwords->elts)->len;
            NGX_ERROR_IF_NULL(
                    ssl->sdf_key = HITLS_SDF_CERT_KeyParse((const char *) key->data, key->len, pass, passLen), ssl->log, "HITLS_SDF_CERT_KeyParse failed.");

            NGX_ERROR_IF_FAIL(
                    HITLS_CFG_SetTlcpPrivateKey(ssl->ctx, ssl->sdf_key, 1, sign_cert_loaded), ssl->log, "HITLS_CFG_SetTlcpPrivateKey failed.");
            sign_cert_loaded = 1;
        } else {
            NGX_ERROR_IF_FAIL(
                    HITLS_CFG_SetTlcpCertificate(ssl->ctx, cert_x509, 1, sign_cert_loaded), ssl->log, "HITLS_CFG_SetTlcpCertificate failed.");
            NGX_ERROR_IF_FAIL(
                    HITLS_CFG_SetTlcpPrivateKey(ssl->ctx, ssl->sdf_key, 1, sign_cert_loaded), ssl->log, "HITLS_CFG_SetTlcpPrivateKey failed.");
            // Adding refCount to key so that ssl->sdf_key is not freed twice.
            CRYPT_EAL_PkeyCtx *ctx = ssl->sdf_key;
            HITLS_SDF_UserPkeyCtx *key = ctx->key;
            key->refCount ++;
        }
        ret = NGX_OK;
        success = 1;
        goto ERR;
    }
#endif

    if (passwords != NULL) {
        ngx_str_t *userdata = (ngx_str_t *) passwords->elts;
        ret = HITLS_CFG_SetDefaultPasswordCbUserdata(ssl->ctx, userdata->data);
        if (ret != NGX_OK) {
            goto ERR;
        }
    }

    cert_key = HITLS_CFG_ParseKey(ssl->ctx, key->data, 0, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_PEM);
    if (cert_key == NULL) {
        goto ERR;
    }
    if (ssl->protocols == NGX_SSL_TLCP) {
        GOTO_ERR_IF_FAIL(
                setTlcpCertificateAndKey(ssl, cert_x509, cert_key), ssl->log, "setTlcpCertificateAndKey failed");
    } else {
        ret =  setTlsCertificateAndKey(ssl, cert_x509, cert_key);
        if (ret != NGX_OK) {
            goto ERR;
        }
    }
    success = 1;
ERR:
    if (cert_key != NULL) {
        CRYPT_PKEY_free(cert_key);
    }
    if (success) {
        return NGX_OK;
    } else {
        return NGX_ERROR;
    }
}

ngx_int_t
ngx_ssl_client_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *cert,
    ngx_int_t depth)
{
    HITLS_CERT_Store *certStore = 0;
    HITLS_CERT_MgrMethod *method = SAL_CERT_GetMgrMethod();
    
    NGX_ERROR_IF_FAIL(
            HITLS_CFG_SetVerifyDepth(ssl->ctx, depth), ssl->log, "HITLS_CFG_SetVerifyDepth failed");

    NGX_ERROR_IF_NULL(
            certStore = HITLS_CFG_GetCertStore(ssl->ctx), ssl->log, "HITLS_GetCertStore returns empty");

    NGX_ERROR_IF_FAIL(
            method->certStoreCtrl(ssl->ctx, certStore, CERT_STORE_CTRL_ADD_CERT_LIST, cert->data, NULL), 
            ssl->log, "method.certStoreCtrl failed");
    
    NGX_ERROR_IF_FAIL(
            HITLS_CFG_SetClientVerifySupport(ssl->ctx, true), ssl->log, "HITLS_CFG_SetClientVerifySupport failed");
    
    return NGX_OK;
}

ngx_int_t
ngx_ssl_trusted_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *cert,
    ngx_int_t depth)
{
    HITLS_CERT_Store *certStore = 0;
    HITLS_CERT_MgrMethod *method = SAL_CERT_GetMgrMethod();

    if (cert->len == 0) return NGX_OK;

    NGX_ERROR_IF_FAIL(
            HITLS_CFG_SetVerifyDepth(ssl->ctx, depth), ssl->log, "HITLS_CFG_SetVerifyDepth failed");
    NGX_ERROR_IF_NULL(
            certStore = HITLS_CFG_GetCertStore(ssl->ctx), ssl->log, "HITLS_GetCertStore returns empty");

    NGX_ERROR_IF_FAIL(
            method->certStoreCtrl(ssl->ctx, certStore, CERT_STORE_CTRL_ADD_CERT_LIST, cert->data, NULL), 
            ssl->log, "certStoreCtrl failed");
    
    NGX_ERROR_IF_FAIL(
            HITLS_CFG_SetClientVerifySupport(ssl->ctx, true), ssl->log, "HITLS_CFG_SetClientVerifySupport");

    return NGX_OK;
}

ngx_int_t
ngx_ssl_crl(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *crl)
{
    ngx_log_error(NGX_LOG_ERR, ssl->log, 0, "ngx_ssl_crl not implemented.\n");
    return NGX_OK;
}

ngx_int_t
ngx_ssl_ocsp(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *responder,
    ngx_uint_t depth, ngx_shm_zone_t *shm_zone)
{
    ngx_log_error(NGX_LOG_EMERG, ssl->log, 0,
                  "\"ssl_ocsp\" is not supported on this platform");

    return NGX_ERROR;
}

ngx_int_t
ngx_ssl_dhparam(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *file)
{
    if (file->len == 0) {
        return NGX_OK;
    }
    ngx_log_error(NGX_LOG_EMERG, ssl->log, 0,
                  "\"dh_param\" is not supported on this platform");
    return NGX_ERROR;
}

ngx_int_t
ngx_ssl_ecdh_curve(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *name)
{
    if (name->len == 4 && strcmp((const char *) name->data, "auto") == 0) {
        return NGX_OK;
    }
    ngx_log_error(NGX_LOG_EMERG, ssl->log, 0,
                  "\"ecdh_curve\" is not supported on this platform");

    return NGX_ERROR;
}

ngx_int_t
ngx_ssl_session_ticket_keys(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_array_t *paths)
{
    if (paths) {
        ngx_log_error(NGX_LOG_WARN, ssl->log, 0,
                      "\"ssl_session_ticket_key\" ignored, not supported");
    }

    return NGX_OK;
}

ngx_int_t
ngx_ssl_stapling(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *file,
    ngx_str_t *responder, ngx_uint_t verify)
{
    ngx_log_error(NGX_LOG_WARN, ssl->log, 0,
                  "\"ssl_stapling\" ignored, not supported");

    return NGX_OK;
}

ngx_int_t
ngx_ssl_early_data(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_uint_t enable)
{
    if (!enable) {
        return NGX_OK;
    }
    return NGX_ERROR;
}

ngx_int_t
ngx_ssl_conf_commands(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_array_t *commands)
{
    if (commands == NULL) {
        return NGX_OK;
    }
    return NGX_ERROR;
}

ngx_int_t
ngx_ssl_get_protocol(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    HITLS_Ctx *ctx;
    HITLS_Session *session;
    unsigned short protocol;

    ctx = c->ssl->connection;
    session = HITLS_GetSession(ctx);
    if (session == NULL)
        goto error;

    if (HITLS_SESS_GetProtocolVersion(session, &protocol))
        goto error;

    if (protocol == HITLS_VERSION_TLCP11) {
        s->data = (unsigned char *) "TLCP";
    } else {
        s->data = (unsigned char *) "TLS1.2";
    }
    return NGX_OK;
error:
    s->data = (unsigned char *) "";
    s->len = 1;
    return NGX_OK;
}

ngx_int_t
ngx_ssl_get_cipher_name(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    unsigned short cipherSuite;
    HITLS_Session *session;

    session = HITLS_GetSession(c->ssl->connection);
    if (session == 0) {
        return NGX_ERROR;
    }

    if (HITLS_SESS_GetCipherSuite(session, &cipherSuite) != HITLS_SUCCESS) {
        return NGX_ERROR;
    }

    switch (cipherSuite) {
    case HITLS_ECDHE_SM4_CBC_SM3:
    case HITLS_ECC_SM4_CBC_SM3:
        s->data = (unsigned char *) "SM4_CBC";
        break;
    default:
        s->data = ngx_pnalloc(pool, 10);
        sprintf((char *) s->data, "0x%x", cipherSuite);
    }

    return NGX_OK;
}
ngx_int_t
ngx_ssl_get_ciphers(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    fprintf(stderr, "MISSING ngx_ssl_get_ciphers implementation.\n");
    return NGX_OK;
}
ngx_int_t
ngx_ssl_get_curve(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    fprintf(stderr, "MISSING get** implementation.\n");
    return NGX_OK;
}
ngx_int_t
ngx_ssl_get_curves(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    fprintf(stderr, "MISSING get** implementation.\n");
    return NGX_OK;
}
ngx_int_t
ngx_ssl_get_session_id(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    HITLS_Ctx *ctx;
    HITLS_Session *session;
    unsigned char sessionId[32];
    unsigned int sessionIdLen = 32;

    ctx = c->ssl->connection;
    session = HITLS_GetSession(ctx);
    if (session == NULL)
        goto error;

    if (HITLS_SESS_GetSessionId(session, sessionId, &sessionIdLen))
        goto error;

    s->data = ngx_pnalloc(pool, 64);
    for (unsigned int i = 0; i < sessionIdLen; i++) {
        char *cursor = (char *) s->data + i * 2;
        sprintf(cursor, "%02x", sessionId[i]);
    }
    s->len = strlen((const char *) s->data);

    return NGX_OK;
error:
    s->data = (unsigned char *) "";
    s->len = 1;
    return NGX_OK;
}
ngx_int_t
ngx_ssl_get_session_reused(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    HITLS_Ctx *ctx;
    unsigned char reused;

    ctx = c->ssl->connection;
    if (HITLS_IsSessionReused(ctx, &reused))
        goto error;

    if (reused) {
        s->data = (unsigned char *) "r";
    } else {
        s->data = (unsigned char *) ".";
    }

    return NGX_OK;
error:
    s->data = (unsigned char *) "";
    s->len = 1;
    return NGX_OK;
}
ngx_int_t
ngx_ssl_get_early_data(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    fprintf(stderr, "MISSING get** implementation.\n");
    return NGX_OK;
}
ngx_int_t
ngx_ssl_get_server_name(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    fprintf(stderr, "MISSING get** implementation.\n");
    return NGX_OK;
}
ngx_int_t
ngx_ssl_get_alpn_protocol(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    fprintf(stderr, "MISSING get** implementation.\n");
    return NGX_OK;
}
ngx_int_t
ngx_ssl_get_certificate(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    fprintf(stderr, "MISSING get** implementation.\n");
    return NGX_OK;
}
ngx_int_t
ngx_ssl_get_raw_certificate(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    fprintf(stderr, "MISSING get** implementation.\n");
    return NGX_OK;
}
ngx_int_t
ngx_ssl_get_escaped_certificate(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    ngx_str_t cert;
    uintptr_t n;
    HITLS_CERT_X509 *clientCert;
    int success = 0;
    cert.data = NULL;
    cert.len = 0;

    clientCert = HITLS_GetPeerCertificate(c->ssl->connection);
    if (clientCert == NULL) {
        goto error;
    }

    cert.data = (unsigned char *) PEM_CERT_ENCODE(clientCert, MIC_ONLY, 0, 0, 0);
    if (cert.data == NULL) {
        goto error;
    }

    cert.len = strlen((char *) cert.data);
    if (cert.len == 0) {
        goto error;
    }

    n = ngx_escape_uri(NULL, cert.data, cert.len, NGX_ESCAPE_URI_COMPONENT);
    s->len = cert.len + n * 2;
    s->data = ngx_pnalloc(pool, s->len);
    if (s->data == NULL) {
        goto error;
    }

    ngx_escape_uri(s->data, cert.data, cert.len, NGX_ESCAPE_URI_COMPONENT);

    success = 1;
error:
    if (cert.data) {
        BSL_SAL_FREE(cert.data);
    }
    if (!success) {
        s->data = (unsigned char *) "";
        s->len = 1;
    }
    return NGX_OK;
}

ngx_int_t
ngx_ssl_get_subject_dn(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    HITLS_CERT_X509 *clientCert = HITLS_GetPeerCertificate(c->ssl->connection);
    if (clientCert == NULL) {
        return NGX_ERROR;
    }
    BSL_Buffer dnName = {NULL, 0};
    int32_t ret = HITLS_X509_CtrlCert(clientCert, HITLS_X509_CERT_GET_SUBJECT_DNNAME, &dnName, sizeof(BSL_Buffer));
    if (ret != HITLS_X509_SUCCESS) {
        goto ERR;
    }

    s->data = ngx_pnalloc(pool, dnName->len);
    if (s->data == NULL) {
        goto ERR;
    }
    s->len = dnName->len;
    ngx_memcpy(s->data, dnName->buff, dnName->len);
 
ERR:
    HITLS_X509_FreeCert(clientCert);
    BSL_SAL_FREE(dnName.buff);
    return NGX_OK;
}

ngx_int_t
ngx_ssl_get_issuer_dn(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    HITLS_CERT_X509 *clientCert = HITLS_GetPeerCertificate(c->ssl->connection);
    if (clientCert == NULL) {
        return NGX_ERROR;
    }

    BSL_Buffer dnName = {NULL, 0};
    int32_t ret = HITLS_X509_CtrlCert(clientCert, HITLS_X509_CERT_GET_ISSUER_DNNAME, &dnName, sizeof(BSL_Buffer));
    if (ret != HITLS_X509_SUCCESS) {
        goto ERR;
    }

    s->data = ngx_pnalloc(pool, dnName->len);
    if (s->data == NULL) {
        goto ERR;
    }
    s->len = dnName->len;
    ngx_memcpy(s->data, dnName->buff, dnName->len);
 
ERR:
    HITLS_X509_FreeCert(clientCert);
    BSL_SAL_FREE(dnName.buff);
    return NGX_OK;
}

ngx_int_t
ngx_ssl_get_subject_dn_legacy(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    fprintf(stderr, "MISSING get** implementation.\n");
    return NGX_OK;
}
ngx_int_t
ngx_ssl_get_issuer_dn_legacy(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    fprintf(stderr, "MISSING get** implementation.\n");
    return NGX_OK;
}
ngx_int_t
ngx_ssl_get_serial_number(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    int success = 0;

    HITLS_CERT_X509 *clientCert = HITLS_GetPeerCertificate(c->ssl->connection);
    if (clientCert == NULL) {
        return NGX_ERROR;
    }

    BSL_Buffer num = {NULL, 0};
    int32_t ret = HITLS_X509_CtrlCert(clientCert, HITLS_X509_CERT_GET_SERIALNUM, &num, sizeof(num));
    if (ret != HITLS_X509_SUCCESS) {
        goto error;
    }


    s->data = ngx_pnalloc(pool, 64);
    for (unsigned int i=0; i < sn->uiLength; i++) {
        char *cursor = (char *) s->data + i * 2;
        sprintf(cursor, "%02x", (unsigned char) sn->aVal[i]);
    }
    s->len = strlen((const char *) s->data);
error:
    HITLS_X509_FreeCert(clientCert);
    return NGX_OK;
}

ngx_int_t
ngx_ssl_get_fingerprint(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    fprintf(stderr, "MISSING get** implementation.\n");
    return NGX_OK;
}
ngx_int_t
ngx_ssl_get_client_verify(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    fprintf(stderr, "MISSING get** implementation.\n");
    return NGX_OK;
}
ngx_int_t
ngx_ssl_get_client_v_start(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    HITLS_CERT_X509 *clientCert = HITLS_GetPeerCertificate(c->ssl->connection);
    if (clientCert == NULL) {
        return NGX_ERROR;
    }

    BSL_TIME time = {0};
    int32_t ret = HITLS_X509_CtrlCert(clientCert, HITLS_X509_CERT_GET_BEFORE_TIME, &time, sizeof(time));
    if (ret != HITLS_X509_SUCCESS) {
        goto error;
    }
    s->len = 16;
    s->data = ngx_pnalloc(pool, s->len);
    sprintf((char *) s->data, "%04d%02d%02d%02d%02d%02dZ",
            time->year, time->month, time->day,
            time->hour, time->minute, time->second);

 
error:
    HITLS_X509_FreeCert(clientCert);
    return NGX_OK;
}

ngx_int_t
ngx_ssl_get_client_v_end(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{

    HITLS_CERT_X509 *clientCert = HITLS_GetPeerCertificate(c->ssl->connection);
    if (clientCert == NULL) {
        return NGX_ERROR;
    }

    BSL_TIME time = {0};
    int32_t ret = HITLS_X509_CtrlCert(clientCert, HITLS_X509_CERT_GET_AFTER_TIME, &time, sizeof(time));
    if (ret != HITLS_X509_SUCCESS) {
        goto error;
    }
    s->len = 16;
    s->data = ngx_pnalloc(pool, s->len);
    sprintf((char *) s->data, "%04d%02d%02d%02d%02d%02dZ",
            time->year, time->month, time->day,
            time->hour, time->minute, time->second);

 
error:
    HITLS_X509_FreeCert(clientCert);
    return NGX_OK;
}

ngx_int_t
ngx_ssl_get_client_v_remain(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    fprintf(stderr, "MISSING get** implementation.\n");
    return NGX_OK;
}

ngx_int_t
ngx_ssl_client_session_cache(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_uint_t enable)
{
    if (HITLS_CFG_SetSessionCacheMode(ssl->ctx, HITLS_SESS_CACHE_CLIENT) != HITLS_SUCCESS) {
        return NGX_ERROR;
    }
    return NGX_OK;
}
