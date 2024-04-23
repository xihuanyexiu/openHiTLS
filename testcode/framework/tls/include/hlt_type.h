/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef HLT_TYPE_H
#define HLT_TYPE_H

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include "uio_base.h"
#include "bsl_uio.h"
#include "hitls_type.h"
#include "tls_config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IP_LEN (32)
#define MAX_CIPHERSUITES_LEN (512)
#define MAX_POINTFORMATS_LEN (512)
#define MAX_GROUPS_LEN (512)
#define MAX_SIGNALGORITHMS_LEN (512)
#define MAX_CERT_LEN (512)
#define PSK_MAX_LEN (256)
#define TICKET_KEY_CB_NAME_LEN (50)
#define MAX_SERVER_NAME_LEN (256)
#define SERVER_NAME_CB_NAME_LEN (50)
#define SERVER_NAME_ARG_NAME_LEN (50)
#define MAX_ALPN_LEN (256)
#define ALPN_CB_NAME_LEN (50)
#define ALPN_DATA_NAME_LEN (50)
#define MAX_NO_RENEGOTIATIONCB_LEN (1024)

#define DEFAULT_CERT_PATH       "../../testcode/testdata/tls/certificate/"

#define ECDSA_RSA_CA_PATH       "ecdsa_rsa_cert/rootCA.pem:ecdsa_rsa_cert/CA1.pem"
#define ECDSA_RSA_CHAIN_PATH    "ecdsa_rsa_cert/CA1.pem"
#define ECDSA_RSA_EE_PATH       "ecdsa_rsa_cert/ee.pem"
#define ECDSA_RSA_PRIV_PATH     "ecdsa_rsa_cert/ee.key.pem"

#define RSA_SHA_CA_PATH         "rsa_sha/root.pem:rsa_sha/intca.pem"
#define RSA_SHA_CHAIN_PATH      "rsa_sha/intca.pem"
#define RSA_SHA1_EE_PATH        "rsa_sha/RSA2048SHA1.pem"
#define RSA_SHA1_PRIV_PATH      "rsa_sha/RSA2048SHA1.key.pem"
#define RSA_SHA384_EE_PATH      "rsa_sha/RSA2048SHA384.pem"
#define RSA_SHA384_PRIV_PATH    "rsa_sha/RSA2048SHA384.key.pem"
#define RSA_SHA512_EE_PATH      "rsa_sha/RSA2048SHA512.pem"
#define RSA_SHA512_PRIV_PATH    "rsa_sha/RSA2048SHA512.key.pem"

#define ECDSA_SHA_CA_PATH       "ecdsa/root.pem:ecdsa/intca.pem"
#define ECDSA_SHA_CHAIN_PATH    "ecdsa/intca.pem"
#define ECDSA_SHA256_EE_PATH    "ecdsa/ec_app256SHA256.pem"
#define ECDSA_SHA256_PRIV_PATH  "ecdsa/ec_app256SHA256.key.pem"
#define ECDSA_SHA384_EE_PATH    "ecdsa/ec_app384SHA384.pem"
#define ECDSA_SHA384_PRIV_PATH  "ecdsa/ec_app384SHA384.key.pem"
#define ECDSA_SHA512_EE_PATH    "ecdsa/ec_app512SHA512.pem"
#define ECDSA_SHA512_PRIV_PATH  "ecdsa/ec_app512SHA512.key.pem"

#define ECDSA_SHA1_CA_PATH      "ecdsa_sha1/ec_root.pem:ecdsa_sha1/ec_intca.pem"
#define ECDSA_SHA1_CHAIN_PATH   "ecdsa_sha1/ec_intca.pem"
#define ECDSA_SHA1_EE_PATH      "ecdsa_sha1/ec_app384SHA1.pem"
#define ECDSA_SHA1_PRIV_PATH    "ecdsa_sha1/ec_app384SHA1.key.pem"

#define RSA_SHA256_CA_PATH      "rsa_sha256/root.pem:rsa_sha256/intca.pem"
#define RSA_SHA256_CHAIN_PATH   "rsa_sha256/intca.pem"
#define RSA_SHA256_EE_PATH1     "rsa_sha256/server.pem"
#define RSA_SHA256_PRIV_PATH1   "rsa_sha256/server.key.pem"
#define RSA_SHA256_EE_PATH2     "rsa_sha256/client.pem"
#define RSA_SHA256_PRIV_PATH2   "rsa_sha256/client.key.pem"
#define RSA_SHA256_EE_PATH3     "rsa_sha/RSA2048SHA256.pem"
#define RSA_SHA256_PRIV_PATH3   "rsa_sha/RSA2048SHA256.key.pem"

#define ECDSA_SHA256_CA_PATH    "ecdsa_sha256/root.pem:ecdsa_sha256/intca.pem"
#define ECDSA_SHA256_CHAIN_PATH "ecdsa_sha256/intca.pem"
#define ECDSA_SHA256_EE_PATH1   "ecdsa_sha256/server.pem"
#define ECDSA_SHA256_PRIV_PATH1 "ecdsa_sha256/server.key.pem"
#define ECDSA_SHA256_EE_PATH2   "ecdsa_sha256/client.pem"
#define ECDSA_SHA256_PRIV_PATH2 "ecdsa_sha256/client.key.pem"

#define DSA_SHA256_CA_PATH      "dss_sha256/dsaCa.pem"
#define DSA_SHA256_CHAIN_PATH   "dss_sha256/dsaSecond.pem"
#define DSA_SHA256_EE_PATH      "dss_sha256/dsaApp.pem"
#define DSA_SHA256_PRIV_PATH    "dss_sha256/dsaApp.key"

#define DSA_SHA1_CA_PATH            "dss_sha1/root.pem"
#define DSA_SHA1_CHAIN_PATH         "dss_sha1/intca.pem"
#define DSA_SHA1_CLIENT_PATH        "dss_sha1/client.pem"
#define DSA_SHA1_CLIENT_PRIV_PATH   "dss_sha1/client.key.pem"
#define DSA_SHA1_SERVER_PATH        "dss_sha1/server.pem"
#define DSA_SHA1_SERVER_PRIV_PATH   "dss_sha1/server.key.pem"

#define SM2_VERIFY_PATH "sm2/root.pem:sm2/ca.pem:sm2/second_ca.pem"
#define SM2_CHAIN_PATH "sm2/ca.pem:sm2/second_ca.pem"
#define SM2_SERVER_ENC_CERT_PATH "sm2/server_enc.pem"
#define SM2_SERVER_ENC_KEY_PATH "sm2/server_enc.key.pem"
#define SM2_SERVER_SIGN_CERT_PATH "sm2/server_sign.pem"
#define SM2_SERVER_SIGN_KEY_PATH "sm2/server_sign.key.pem"
#define SM2_CLIENT_ENC_CERT_PATH "sm2/client_enc.pem"
#define SM2_CLIENT_ENC_KEY_PATH "sm2/client_enc.key.pem"
#define SM2_CLIENT_SIGN_CERT_PATH "sm2/client_sign.pem"
#define SM2_CLIENT_SIGN_KEY_PATH "sm2/client_sign.key.pem"


#define DSA_SHA256_LEN_512_CA_PATH             "securitylevel/dsa/dsa_512_ca.pem"
#define DSA_SHA256_LEN_512_EE_PATH             "securitylevel/dsa/dsa_512_App.pem"
#define DSA_SHA256_LEN_512_KEY_PATH             "securitylevel/dsa/dsa_512_App.key"
#define DSA_SHA256_LEN_1024_CA_PATH             "dss_sha256/dsaCa.pem"
#define DSA_SHA256_LEN_1024_CHAIN_PATH          "dss_sha256/dsaSecond.pem"
#define DSA_SHA256_LEN_1024_EE_PATH             "dss_sha256/dsaApp.pem"
#define DSA_SHA256_LEN_1024_KEY_PATH            "dss_sha256/dsaApp.key"
#define DSA_SHA256_LEN_2048_CA_PATH             "securitylevel/dsa/dsa_2048_ca.pem"
#define DSA_SHA256_LEN_2048_EE_PATH             "securitylevel/dsa/dsa_2048_App.pem"
#define DSA_SHA256_LEN_2048_KEY_PATH             "securitylevel/dsa/dsa_2048_App.key"
#define DSA_SHA256_LEN_3072_CA_PATH             "securitylevel/dsa/dsa_3072_ca.pem"
#define DSA_SHA256_LEN_3072_EE_PATH             "securitylevel/dsa/dsa_3072_App.pem"
#define DSA_SHA256_LEN_3072_KEY_PATH             "securitylevel/dsa/dsa_3072_App.key"
#define DSA_SHA256_LEN_8192_CA_PATH             "securitylevel/dsa/dsa_8192_ca.pem"
#define DSA_SHA256_LEN_8192_EE_PATH             "securitylevel/dsa/dsa_8192_App.pem"
#define DSA_SHA256_LEN_8192_KEY_PATH             "securitylevel/dsa/dsa_8192_App.key"

#define ECDSA_SHA256_LEN_112_CA_PATH                "securitylevel/ecc/ecc_ca_112.pem"
#define ECDSA_SHA256_LEN_112_EE_PATH                "securitylevel/ecc/ecc_app_112.pem"
#define ECDSA_SHA256_LEN_112_KEY_PATH                "securitylevel/ecc/ecc_app_112.key"
#define ECDSA_SHA256_LEN_160_CA_PATH                "securitylevel/ecc/ecc_ca_160.pem"
#define ECDSA_SHA256_LEN_160_EE_PATH                "securitylevel/ecc/ecc_app_160.pem"
#define ECDSA_SHA256_LEN_160_KEY_PATH                "securitylevel/ecc/ecc_app_160.key"
#define ECDSA_SHA256_LEN_224_CA_PATH                "securitylevel/ecc/ecc_ca_224.pem"
#define ECDSA_SHA256_LEN_224_EE_PATH                "securitylevel/ecc/ecc_app_224.pem"
#define ECDSA_SHA256_LEN_224_KEY_PATH                "securitylevel/ecc/ecc_app_244.key"

#define RSA_SHA256_LEN_512_CA_PATH              "securitylevel/rsa/rsa_ca_512.pem"
#define RSA_SHA256_LEN_512_EE_PATH              "securitylevel/rsa/rsa_ee_512.pem"
#define RSA_SHA256_LEN_512_KEY_PATH             "securitylevel/rsa/rsa_ee_512.key"
#define RSA_SHA256_LEN_1024_CA_PATH             "securitylevel/rsa/rsa_ca_1024.pem"
#define RSA_SHA256_LEN_1024_EE_PATH             "securitylevel/rsa/rsa_ee_1024.pem"
#define RSA_SHA256_LEN_1024_KEY_PATH            "securitylevel/rsa/rsa_ee_1024.key"
#define RSA_SHA_LEN_2048_CA_PATH                "rsa_sha/root.pem:rsa_sha/intca.pem"
#define RSA_SHA_LEN_2048_CHAIN_PATH             "rsa_sha/intca.pem"
#define RSA_SHA384_LEN_2048_EE_PATH             "rsa_sha/RSA2048SHA384.pem"
#define RSA_SHA384_LEN_2048_KEY_PATH            "rsa_sha/RSA2048SHA384.key.pem"
#define RSA_SHA256_LEN_3072_CA_PATH             "securitylevel/rsa/rsa_ca_3072.pem"
#define RSA_SHA256_LEN_3072_EE_PATH             "securitylevel/rsa/rsa_ee_3072.pem"
#define RSA_SHA256_LEN_3072_KEY_PATH            "securitylevel/rsa/rsa_ee_3072.key"
#define RSA_SHA256_LEN_8192_CA_PATH             "securitylevel/rsa/rsa_ca_8192.pem"
#define RSA_SHA256_LEN_8192_EE_PATH             "securitylevel/rsa/rsa_ee_8192.pem"
#define RSA_SHA256_LEN_8192_KEY_PATH            "securitylevel/rsa/rsa_ee_8192.key"
#define RSA_SHA256_LEN_15360_CA_PATH             "securitylevel/rsa/rsa_ca_15360.pem"
#define RSA_SHA256_LEN_15360_EE_PATH             "securitylevel/rsa/rsa_ee_15360.pem"
#define RSA_SHA256_LEN_15360_KEY_PATH            "securitylevel/rsa/rsa_ee_15360.key"

typedef struct ProcessSt HLT_Process;

typedef enum {
    HITLS,
} TLS_TYPE;

typedef enum {
    CLIENT,
    SERVER
} TLS_ROLE;

typedef enum {
    DTLS_ALL,
    DTLS1_0,
    DTLS1_2,
    TLS_ALL,
    SSL3_0,
    TLS1_0,
    TLS1_1,
    TLS1_2,
    TLS1_3,
    TLCP1_1,
} TLS_VERSION;

typedef enum {
    TCP = 0,    /**< TCP protocol */
    SCTP = 1,   /**< SCTP protocol */
    NONE_TYPE = 10,
} HILT_TransportType;

typedef enum {
    CERT_CALLBACK_DEFAULT,
} CertCallbackType;

typedef enum {
    MEM_CALLBACK_DEFAULT,
} MemCallbackType;

typedef enum {
    HITLS_CALLBACK_DEFAULT,
} TlsCallbackType;

typedef enum {
    COOKIE_CB_DEFAULT, // Normal cookie callback
    COOKIE_CB_LEN_0,   // The length of the generated cookie is 0
} CookieCallbackType;

typedef struct {
    struct sockaddr_in sockAddr;
    HILT_TransportType type;
    char ip[IP_LEN];
    int port;
    int bindFd;
    bool isBlock;
} DataChannelParam;

typedef struct {
    struct sockaddr_in sockAddr;
    int connPort;
    int srcFd;
    int peerFd;
} HLT_FD;

typedef enum {
    SERVER_CTX_SET_TRUE = 1,
    SERVER_CTX_SET_FALSE = 2,
    SERVER_CFG_SET_TRUE = 3,
    SERVER_CFG_SET_FALSE = 4,
} HILT_SupportType;

typedef struct {
    uint16_t mtu;        // Set the MTU in the dtls.
    // The maximum version number and minimum version number must be both TLS and DTLS.
    // Currently, only DTLS 1.2 is supported
    uint32_t minVersion;
    uint32_t maxVersion;

    char cipherSuites[MAX_CIPHERSUITES_LEN]; // cipher suite
    char tls13CipherSuites[MAX_CIPHERSUITES_LEN]; // TLS13 cipher suite
    char pointFormats[MAX_POINTFORMATS_LEN]; // ec Point Format
    // According to RFC 8446 4.2.7, before TLS 1.3: ec curves; TLS 1.3: group supported by the key exchange.
    char groups[MAX_GROUPS_LEN];
    char signAlgorithms[MAX_SIGNALGORITHMS_LEN]; // signature algorithm

    char serverName[MAX_SERVER_NAME_LEN];      // Client server_name
    //  Name of the server_name callback function for processing the first handshake on the server
    char sniDealCb[SERVER_NAME_CB_NAME_LEN];
    // name of the value function related to the server_name registered by the product
    char sniArg[SERVER_NAME_ARG_NAME_LEN];

    char alpnList[MAX_ALPN_LEN];               // alpn
    char alpnUserData[ALPN_CB_NAME_LEN];
    char alpnSelectCb[ALPN_DATA_NAME_LEN];     // Application Layer Protocol Select Callback
    /* Callback function when the peer end does not support security renegotiation */
    char noSecRenegotiationCb[MAX_NO_RENEGOTIATIONCB_LEN];

    // Indicates whether renegotiation is supported. The default value is False, indicating that renegotiation is not
    // supported
    bool isSupportRenegotiation;
    int  SupportType;                   // 1:The server algorithm is preferred
    bool needCheckKeyUsage;             // Client verification is supported. The default value is False
    // Indicates whether to allow the empty certificate list on the client. The default value is False
    bool isSupportClientVerify;
    bool isSupportNoClientCert;         // supports extended master keys. The default value is True
    // The handshake will be continued regardless of the verification result. for server and client
    bool isSupportVerifyNone;
    bool isSupportPostHandshakeAuth;    // Indicates whether to support post handshake auth. The default value is false.
    bool isSupportExtendMasterSecret;   // supports extended master keys. The default value is True
    bool isSupportSessionTicket;        // Support session ticket
    bool isEncryptThenMac;              // Encrypt-then-mac is supported
    // Users can set the DH parameter to be automatically selected. If the switch is enabled,
    // the DH parameter is automatically selected based on the length of the certificate private key
    bool isSupportDhAuto;
	int32_t setSessionCache;            // Setting the Session Storage Mode
    uint32_t keyExchMode;               // TLS1.3 key exchange mode
    void *infoCb;                       // connection establishment callback function
    void *msgCb;                        // Message callback function
    void *msgArg;                       // Message callback parameter function
    // Indicates whether to enable the function of sending handshake information by flight
    bool isFlightTransmitEnable;
    bool isNoSetCert;                   // Indicates whether the certificate does not need to be set
	int32_t securitylevel;                  // Security level

    char psk[PSK_MAX_LEN];              // psk password
    char ticketKeyCb[TICKET_KEY_CB_NAME_LEN]; // ticket key Callback Function Name

    char eeCert[MAX_CERT_LEN];
    char privKey[MAX_CERT_LEN];
    char signCert[MAX_CERT_LEN];
    char signPrivKey[MAX_CERT_LEN];
    char password[MAX_CERT_LEN];
    char caCert[MAX_CERT_LEN];
    char chainCert[MAX_CERT_LEN];

    bool isClient;
} HLT_Ctx_Config;

typedef struct {
    struct sockaddr_in sockAddr;
    int connPort;
    int sockFd;
    HILT_TransportType connType;
    int SupportType;                   // 3:The server algorithm is preferred
    int sctpCtrlCmd;
} HLT_Ssl_Config;

typedef struct {
    void *ctx; // hitls config
    void *ssl; // hitls ctx
    int ctxId;
    int sslId;
    unsigned long int acceptId;
} HLT_Tls_Res;

typedef enum {
    EXP_NONE,
    EXP_IO_BUSY,
    EXP_RECV_BUF_EMPTY,
} HLT_ExpectIoState;

typedef enum {
    POINT_NONE,
    POINT_RECV,
    POINT_SEND,
} HLT_PointType;

/**
 * @brief   msg processing callback
 */
typedef void (*HLT_FrameCallBack)(void *msg, void *userData);

typedef struct {
    BSL_UIO_Method method;         /**< User-defined message sending and receiving control function */
    HLT_FrameCallBack frameCallBack; /**< msg processing callback */
    void *ctx;                       /**< TLS context */
    int32_t expectReType;            /**< Corresponding enumeration REC_Type */
    int32_t expectHsType;            /**< Corresponding enumerated value HS_MsgType */
    HLT_ExpectIoState ioState;       /**< customized I/O status */
    HLT_PointType pointType;         /**< Callback function for recording keys */
    void *userData;                  /**< Customized data, which will be transferred to the msg processing callback */
} HLT_FrameHandle;

#if (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define TIME_OUT_SEC 50
#else
#define TIME_OUT_SEC 8
#endif

#ifdef __cplusplus
}
#endif

#endif // HLT_TYPE_H
