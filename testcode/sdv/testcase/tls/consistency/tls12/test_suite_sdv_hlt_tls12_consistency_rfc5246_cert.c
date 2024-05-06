/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */
/* BEGIN_HEADER */
/* INCLUDE_BASE test_suite_tls12_consistency_rfc5246 */
/* END_HEADER */

/* @
* @test  SDV_TLS_TLS12_RFC5246_CONSISTENCY_CIPHER_SUITE_NOT_SUITABLE_CERT_TC001
* @title  The public key algorithm used to verify the server terminal certificate must match the algorithm suite.
* @precon  nan
* @brief  1. Create a config file, configure the server certificate as the ECDSA public key, and configure the ECDHE_RSA algorithm suite in the hello message on the client.
          2. The client invokes the HITLS_Connect interface. (Expected result 1)
* @expect 1. A failure message is returned.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_CIPHER_SUITE_NOT_SUITABLE_CERT_TC001(void)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, false);
    ASSERT_TRUE(remoteProcess != NULL);

    // Create a config file, configure the server certificate as the ECDSA public key, and configure the ECDHE_RSA algorithm suite in the hello message on the client.
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);

    TestSetCertPath(serverCtxConfig, "CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256");
    serverRes = HLT_ProcessTlsAccept(localProcess, TLS1_2, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL); // failed in

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);

    TestSetCertPath(clientCtxConfig, "CERT_SIG_SCHEME_RSA_PKCS1_SHA256");
    HLT_SetGroups(clientCtxConfig, "HITLS_EC_GROUP_SECP256R1");
    HLT_SetCipherSuites(clientCtxConfig, "HITLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256");
    HLT_SetSignature(clientCtxConfig, "CERT_SIG_SCHEME_RSA_PKCS1_SHA256");

    // The client invokes the HITLS_Connect interface.
    clientRes = HLT_ProcessTlsConnect(remoteProcess, TLS1_2, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes == NULL);

exit:
    HLT_FreeAllProcess();
    return;
}
/* END_CASE */

/* @
* @test  SDV_TLS_TLS12_RFC5246_CONSISTENCY_CLIENT_NOTSET_CERT_TC001
* @title  The certificate chain sent by the server does not contain the root certificate.
* @precon  nan
* @brief  If no certificate is set on the client and the server sends a complete certificate chain,
*         link establishment fails.
* @expect 1. A failure message is returned.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_CLIENT_NOTSET_CERT_TC001(void)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverCtxConfig = NULL;
    HLT_Ctx_Config *clientCtxConfig = NULL;
    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, true);
    ASSERT_TRUE(remoteProcess != NULL);

    serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);

    TestSetCertPath(serverCtxConfig, "CERT_SIG_SCHEME_RSA_PKCS1_SHA256");

    clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    HLT_SetCipherSuites(clientCtxConfig, "HITLS_RSA_WITH_AES_256_CBC_SHA");
    HLT_SetSignature(clientCtxConfig, "CERT_SIG_SCHEME_RSA_PKCS1_SHA256");

    serverRes = HLT_ProcessTlsAccept(localProcess, TLS1_2, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    /* If no certificate is set on the client and the server sends a complete certificate chain,link establishment
     * fails. */
    clientRes = HLT_ProcessTlsConnect(remoteProcess, TLS1_2, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes == NULL);
exit:
    HLT_FreeAllProcess();
}
/* END_CASE */

/* @
* @test  SDV_TLS_TLS12_RFC5246_CONSISTENCY_SERVER_WITHOUT_ROOT_CERT_TC001
* @title  The certificate chain sent by the server does not contain the root certificate.
* @precon nan
* @brief  Set the root certificate and send a certificate chain that does not contain the root certificate.
*         The link is successfully set up.
* @expect 1. Return a success message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_SERVER_WITHOUT_ROOT_CERT_TC001(void)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverCtxConfig = NULL;
    HLT_Ctx_Config *clientCtxConfig = NULL;
    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, true);
    ASSERT_TRUE(remoteProcess != NULL);

    serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);

    TestSetCertPath(serverCtxConfig, "CERT_SIG_SCHEME_RSA_PKCS1_SHA256");
    HLT_SetClientVerifySupport(serverCtxConfig, true);

    // Set the root certificate and send a certificate chain that does not contain the root certificate.
    clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    TestSetCertPath(clientCtxConfig, "CERT_SIG_SCHEME_RSA_PKCS1_SHA256");
    HLT_SetClientVerifySupport(clientCtxConfig, true);
    HLT_SetCipherSuites(clientCtxConfig, "HITLS_RSA_WITH_AES_256_CBC_SHA");
    HLT_SetSignature(clientCtxConfig, "CERT_SIG_SCHEME_RSA_PKCS1_SHA256");

    serverRes = HLT_ProcessTlsAccept(localProcess, TLS1_2, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    clientRes = HLT_ProcessTlsConnect(remoteProcess, TLS1_2, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);
exit:
    HLT_FreeAllProcess();
}
/* END_CASE */

/* @
* @test  SDV_TLS_TLS12_RFC5246_CONSISTENCY_CLIENT_SET_ERRO_ROOT_CERT_TC001
* @title  The certificate chain sent by the server does not contain the root certificate.
* @precon nan
* @brief  The root certificate is incorrectly set on the client. As a result, the link fails to be established.
* @expect 1. A failure message is returned.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_CLIENT_SET_ERRO_ROOT_CERT_TC001(void)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, false);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);

    TestSetCertPath(serverCtxConfig, "CERT_SIG_SCHEME_RSA_PKCS1_SHA256");

    serverRes = HLT_ProcessTlsAccept(localProcess, TLS1_2, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    // The root certificate is incorrectly set on the client.
    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);

    HLT_SetCertPath(clientCtxConfig, "rsa_sha512/otherRoot.crt", "rsa_sha512/otherInter.crt",
        "rsa_sha512/otherInter2.crt", "rsa_sha512/otherInter2.key", "NULL", "NULL");

    HLT_SetCipherSuites(clientCtxConfig, "HITLS_RSA_WITH_AES_256_CBC_SHA");
    HLT_SetSignature(clientCtxConfig, "CERT_SIG_SCHEME_RSA_PKCS1_SHA256");

    clientRes = HLT_ProcessTlsConnect(remoteProcess, TLS1_2, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes == NULL);
exit:
    HLT_FreeAllProcess();
    return;
}
/* END_CASE */

/**
 * Set the certificate signature certSig to DSA_SHA256.
 * Set ciphersuite to HITLS_DHE_DSS_WITH_AES_128_GCM_SHA256.
 * If the signature type in the cipher suite matches that in the certificate, the connection is successfully established.
 */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_CIPHERSUITE_SIG_MATCH_CERT_SIG_TC001()
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    int ret = 0;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, false);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);

    HLT_SetCertPath(serverCtxConfig, "dss_sha256/dsaCa.pem", "dss_sha256/dsaSecond.pem", "dss_sha256/dsaApp.pem",
        "dss_sha256/dsaApp.key", "NULL", "NULL");
    HLT_SetCipherSuites(serverCtxConfig, "HITLS_DHE_DSS_WITH_AES_128_GCM_SHA256");

    serverRes = HLT_ProcessTlsAccept(localProcess, TLS1_2, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);

    HLT_SetCertPath(clientCtxConfig, "dss_sha256/dsaCa.pem", "dss_sha256/dsaSecond.pem", "NULL", "NULL", "NULL",
        "NULL");
    HLT_SetCipherSuites(clientCtxConfig, "HITLS_DHE_DSS_WITH_AES_128_GCM_SHA256");
    HLT_SetSignature(clientCtxConfig, "CERT_SIG_SCHEME_DSA_SHA256");

    clientRes = HLT_ProcessTlsConnect(remoteProcess, TLS1_2, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ret = HLT_GetTlsAcceptResult(serverRes);
    ASSERT_TRUE(ret == 0);

    ret = HLT_ProcessTlsWrite(localProcess, serverRes, (uint8_t *)"Hello World", strlen("Hello World"));
    ASSERT_TRUE(ret == 0);

    uint8_t readBuf[1000] = {0};
    uint32_t readLen;
    ret = HLT_ProcessTlsRead(remoteProcess, clientRes, readBuf, 1000, &readLen);
    ASSERT_TRUE(ret == 0);
    ASSERT_TRUE(readLen == strlen("Hello World"));
    ASSERT_TRUE(memcmp("Hello World", readBuf, readLen) == 0);

exit:
    HLT_FreeAllProcess();
}
/* END_CASE */

/**
 * Configure the certificate signature as CERT_SIG_SCHEME_RSA_PKCS1_SHA256.
 * Set the algorithm suite to HITLS_DHE_DSS_WITH_AES_128_GCM_SHA256.
 * The signature type in the cipher suite does not match that in the certificate,
 * Expected link establishment failure, as shown in the log.
 * select certificate fail
 * have no suitable cert
 * can not find a appropriate cipher suite
 */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_CIPHERSUITE_SIG_MATCH_CERT_SIG_TC002()
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, false);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);

    HLT_SetCertPath(serverCtxConfig, "rsa_sha256/root.pem:rsa_sha256/intca.pem", "rsa_sha256/intca.pem",
        "rsa_sha256/server.pem", "rsa_sha256/server.key.pem", "NULL", "NULL");
    HLT_SetCipherSuites(serverCtxConfig, "HITLS_DHE_RSA_WITH_AES_128_GCM_SHA256");

    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLS1_2, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);

    HLT_SetCertPath(clientCtxConfig, "rsa_sha256/root.pem:rsa_sha256/intca.pem", "NULL", "NULL", "NULL", "NULL",
        "NULL");
    // Set the algorithm suite to HITLS_DHE_DSS_WITH_AES_128_GCM_SHA256.
    HLT_SetCipherSuites(clientCtxConfig, "HITLS_DHE_DSS_WITH_AES_128_GCM_SHA256");

    clientRes = HLT_ProcessTlsConnect(localProcess, TLS1_2, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes == NULL);

exit:
    HLT_FreeAllProcess();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_CIPHERSUITE_SIG_MATCH_CERT_SIG_TC003()
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    // Create the local process and peer process.
    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, false);
    ASSERT_TRUE(remoteProcess != NULL);

    // Configure link information on the server.
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);

    HLT_SetCertPath(serverCtxConfig, "dss_sha256/dsaCa.pem", "dss_sha256/dsaSecond.pem", "dss_sha256/dsaApp.pem",
        "dss_sha256/dsaApp.key", "NULL", "NULL");
    HLT_SetCipherSuites(serverCtxConfig, "HITLS_DHE_DSS_WITH_AES_128_GCM_SHA256");

    // The server listens on the TLS link.
    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLS1_2, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    // Configure link information on the client.
    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);

    HLT_SetCertPath(clientCtxConfig, "dss_sha256/dsaCa.pem", "dss_sha256/dsaSecond.pem", "NULL", "NULL", "NULL",
        "NULL");
    HLT_SetCipherSuites(clientCtxConfig, "HITLS_DHE_DSS_WITH_AES_128_GCM_SHA256:HITLS_DHE_RSA_WITH_AES_128_GCM_SHA256");
    // Set the signature extension in the client hello message.
    HLT_SetSignature(clientCtxConfig, "CERT_SIG_SCHEME_RSA_PKCS1_SHA256");

    // The client fails to establish a TLS link.
    clientRes = HLT_ProcessTlsConnect(localProcess, TLS1_2, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes == NULL);

exit:
    HLT_FreeAllProcess();
}
/* END_CASE */

/* @
* @test  SDV_TLS_TLS12_RFC5246_CONSISTENCY_KEYUSAGE_CERT_TC001
* @title  The keyusage extension of the server certificate does not contain the keyEncipherment usage.
*         As a result, the link fails to be established.
* @precon  nan
* @brief  1. Set the server certificate to an RSA certificate that contains the keyusage extension,
          The extension does not contain the keyEncipherment usage.
          The negotiation cipher suite is the RSA cipher suite. Expected result 1 is obtained.
* @expect 1. connection setup failed
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_KEYUSAGE_CERT_TC001()
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, false);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);

    HLT_SetCertPath(serverCtxConfig, "rsa_sha512/root.pem", "rsa_sha512/intca.pem",
        "rsa_sha512/usageKeyEncipher.crt", "rsa_sha512/usageKeyEncipher.key", "NULL", "NULL");
    HLT_SetCipherSuites(serverCtxConfig, "HITLS_RSA_WITH_AES_256_GCM_SHA384");

    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLS1_2, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);

    HLT_SetCertPath(clientCtxConfig, "rsa_sha512/root.pem", "rsa_sha512/intca.pem",
        "rsa_sha512/server.pem", "rsa_sha512/server.key.pem",  "NULL", "NULL");
    clientCtxConfig->needCheckKeyUsage = true;

    clientRes = HLT_ProcessTlsConnect(localProcess, TLS1_2, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes == NULL);
exit:
    HLT_FreeAllProcess();
}
/* END_CASE */

/* @
* @test  SDV_TLS_TLS12_RFC5246_CONSISTENCY_KEYUSAGE_CERT_TC002
* @title  Failed to set up the link because the keyuage extension does not match.
* @precon  nan
* @brief  1. Configure the server certificate with the keyuage extension and do not support digitalSignature.
          Expected result 1 is obtained.
* @expect 1. connection setup failed
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_KEYUSAGE_CERT_TC002()
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, false);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);

    HLT_SetCertPath(serverCtxConfig, "rsa_sha512/root.pem", "rsa_sha512/intca.pem",
        "rsa_sha512/usagedigitalSign.crt", "rsa_sha512/usagedigitalSign.key", "NULL", "NULL");

    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLS1_2, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);

    HLT_SetCertPath(clientCtxConfig, "rsa_sha512/root.pem", "rsa_sha512/intca.pem",
        "rsa_sha512/server.pem", "rsa_sha512/server.key.pem",  "NULL", "NULL");
    clientCtxConfig->needCheckKeyUsage = true;

    clientRes = HLT_ProcessTlsConnect(localProcess, TLS1_2, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes == NULL);
exit:
    HLT_FreeAllProcess();
}
/* END_CASE */