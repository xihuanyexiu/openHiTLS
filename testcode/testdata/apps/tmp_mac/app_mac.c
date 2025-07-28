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

#include "app_mac.h"
#include <linux/limits.h>
#include "string.h"
#include "securec.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_eal_mac.h"
#include "bsl_errno.h"
#include "app_opt.h"
#include "app_function.h"
#include "app_list.h"
#include "app_errno.h"
#include "app_help.h"
#include "app_print.h"
#include "app_provider.h"

#define MAX_BUFSIZE (1024 * 8)  // Indicates the length of a single mac during mac calculation.
#define IS_SUPPORT_GET_EOF 1
#define MAC_MAX_KEY_LEN 64
#define MAC_MAX_IV_LENGTH 16
#define MAC_MAX_FILENAME_LENGTH  PATH_MAX
#define MAC_HEX_HEAD "0x"
#define HEX_TO_BYTE 2

typedef enum OptionChoice {
    HITLS_APP_OPT_MAC_ERR = -1,
    HITLS_APP_OPT_MAC_EOF = 0,
    HITLS_APP_OPT_MAC_HELP = 1,  // The value of the help type of each opt option is 1. The following can be customized.
    HITLS_APP_OPT_MAC_ALG,
    HITLS_APP_OPT_MAC_IN,
    HITLS_APP_OPT_MAC_OUT,
    HITLS_APP_OPT_MAC_BINARY,
    HITLS_APP_OPT_MAC_KEY,
    HITLS_APP_OPT_MAC_HEXKEY,
    HITLS_APP_OPT_MAC_IV,
    HITLS_APP_OPT_MAC_HEXIV,
    HITLS_APP_OPT_MAC_TAGLEN,
    HITLS_APP_PROV_ENUM
} HITLSOptType;

const HITLS_CmdOption g_macOpts[] = {
    {"help", HITLS_APP_OPT_MAC_HELP, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Display this function summary"},
    {"name", HITLS_APP_OPT_MAC_ALG, HITLS_APP_OPT_VALUETYPE_STRING, "Mac algorithm"},
    {"in", HITLS_APP_OPT_MAC_IN, HITLS_APP_OPT_VALUETYPE_IN_FILE, "Mac request input file (default stdin)"},
    {"out", HITLS_APP_OPT_MAC_OUT, HITLS_APP_OPT_VALUETYPE_OUT_FILE,
        "Specify the output file for the MAC result (default: stdout)"},
    {"binary", HITLS_APP_OPT_MAC_BINARY, HITLS_APP_OPT_VALUETYPE_NO_VALUE,
        "Enable binary output format for the MAC result"},
    {"key", HITLS_APP_OPT_MAC_KEY, HITLS_APP_OPT_VALUETYPE_STRING,
        "Specify the encryption key for the MAC operation"},
    {"hexkey", HITLS_APP_OPT_MAC_HEXKEY, HITLS_APP_OPT_VALUETYPE_STRING,
        "Specify the hexadecimal encryption key for the MAC operation"},
    {"iv", HITLS_APP_OPT_MAC_IV, HITLS_APP_OPT_VALUETYPE_STRING,
        "Set the initialization vector for the MAC operation"},
    {"hexiv", HITLS_APP_OPT_MAC_HEXIV, HITLS_APP_OPT_VALUETYPE_STRING,
        "Set the initialization vector in hexadecimal format for the MAC operation"},
    {"taglen", HITLS_APP_OPT_MAC_TAGLEN, HITLS_APP_OPT_VALUETYPE_INT,
        "Set the length of the authentication tag for the MAC operation"},
    HITLS_APP_PROV_OPTIONS,
    {NULL}};

typedef struct {
    char *algName;
    int32_t algId;
    uint32_t macSize;
    uint32_t isBinary;
    char *inFile;
    char *outFile;
    char *key;
    char *hexKey;
    uint32_t keyLen;
    char *iv;
    char *hexIv;
    uint32_t tagLen;
    AppProvider *provider;
} MacOpt;

static int32_t HandleOpt(MacOpt *macOpt)
{
    int32_t macOptType;
    while ((macOptType = HITLS_APP_OptNext()) != HITLS_APP_OPT_EOF) {
        switch (macOptType) {
            case HITLS_APP_OPT_MAC_EOF:
                break;
            case HITLS_APP_OPT_MAC_ERR:
                AppPrintError("enc: Use -help for summary.\n");
                return HITLS_APP_OPT_UNKOWN;
            case HITLS_APP_OPT_MAC_HELP:
                HITLS_APP_OptHelpPrint(g_macOpts);
                return HITLS_APP_HELP;
            case HITLS_APP_OPT_MAC_IN:
                macOpt->inFile = HITLS_APP_OptGetValueStr();
                break;
            case HITLS_APP_OPT_MAC_OUT:
                macOpt->outFile = HITLS_APP_OptGetValueStr();
                break;
            case HITLS_APP_OPT_MAC_KEY:
                macOpt->key = HITLS_APP_OptGetValueStr();
                break;
            case HITLS_APP_OPT_MAC_HEXKEY:
                macOpt->hexKey = HITLS_APP_OptGetValueStr();
                break;
            case HITLS_APP_OPT_MAC_IV:
                macOpt->iv = HITLS_APP_OptGetValueStr();
                break;
            case HITLS_APP_OPT_MAC_HEXIV:
                macOpt->hexIv = HITLS_APP_OptGetValueStr();
                break;
            case HITLS_APP_OPT_MAC_PROVIDER:
                macOpt->provider->providerName = HITLS_APP_OptGetValueStr();
                break;
            case HITLS_APP_OPT_MAC_PROVIDER_PATH:
                macOpt->provider->providerPath = HITLS_APP_OptGetValueStr();
                break;
            case HITLS_APP_OPT_MAC_PROVIDER_ATTR:
                macOpt->provider->providerAttr = HITLS_APP_OptGetValueStr();
                break;
            case HITLS_APP_OPT_MAC_BINARY:
                macOpt->isBinary = 1;
                break;
            case HITLS_APP_OPT_MAC_TAGLEN:
                if (HITLS_APP_OptGetUint32(HITLS_APP_OptGetValueStr(), &(macOpt->tagLen)) != HITLS_APP_SUCCESS) {
                    return HITLS_APP_OPT_UNKOWN;
                }
                break;
            case HITLS_APP_OPT_MAC_ALG:
                macOpt->algName = HITLS_APP_OptGetValueStr();
                if (macOpt->algName == NULL) {
                    return HITLS_APP_OPT_VALUE_INVALID;
                }
                macOpt->algId = HITLS_APP_GetCidByName(macOpt->algName, HITLS_APP_LIST_OPT_MAC_ALG);
                if (macOpt->algId == BSL_CID_UNKNOWN) {
                    return HITLS_APP_OPT_VALUE_INVALID;
                }
                break;
            default:
                break;
        }
    }
    // Obtain the number of parameters that cannot be parsed in the current version
    // and print the error information and help list.
    if (HITLS_APP_GetRestOptNum() != 0) {
        AppPrintError("Extra arguments given.\n");
        AppPrintError("enc: Use -help for summary.\n");
        return HITLS_APP_OPT_UNKOWN;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t CheckParam(MacOpt *macOpt)
{
    if (macOpt->algId < 0) {
        macOpt->algId = CRYPT_MAC_HMAC_SHA256;
    }

    if (macOpt->tagLen <= 0 && macOpt->algId >= 2019 && macOpt->algId <= 2021) {
        AppPrintError("The input tagLen is invalid.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }

    if (macOpt->inFile != NULL && strlen((const char*)macOpt->inFile) > MAC_MAX_FILENAME_LENGTH) {
        AppPrintError("The input file length is invalid.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }

    if (macOpt->outFile != NULL && strlen((const char*)macOpt->outFile) > MAC_MAX_FILENAME_LENGTH) {
        AppPrintError("The output file length is invalid.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t HexToByte(const char *hex, uint8_t **bin, uint32_t *len)
{
    uint32_t hexLen = strlen(hex);
    const char *num = hex;
    // Skip the preceding zeros.
    for (uint32_t i = 0; i < hexLen; ++i) {
        if (num[i] != '0' && (i + 1) != hexLen) {
            num += i;
            hexLen -= i;
            break;
        }
    }
    *len = (hexLen + 1) / HEX_TO_BYTE;
    uint8_t *res = BSL_SAL_Malloc(*len);
    if (res == NULL) {
        AppPrintError("MAC: Allocate memory of serial failed.\n");
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    uint32_t hexIdx = 0;
    uint32_t binIdx = 0;
    char *endptr;
    char tmp[] = {'0', '0', '\0'};
    while (hexIdx < hexLen) {
        if (hexIdx == 0 && hexLen % HEX_TO_BYTE == 1) {
            tmp[0] = '0';
        } else {
            tmp[0] = hex[hexIdx++];
        }
        tmp[1] = hex[hexIdx++];
        res[binIdx++] = (uint32_t)strtol(tmp, &endptr, 16);  // 16: hex
        if (*endptr != '\0') {
            BSL_SAL_Free(res);
            return HITLS_APP_OPT_VALUE_INVALID;
        }
    }

    *bin = res;
    return HITLS_APP_SUCCESS;
}

static CRYPT_EAL_MacCtx *InitAlgMac(MacOpt *macOpt)
{
    uint8_t *key = NULL;
    uint32_t keyLen = MAC_MAX_KEY_LEN;
    int32_t ret;

    if (macOpt->provider->providerName == NULL) {
        macOpt->provider->providerName = "default";
    }
    ret = HITLS_APP_LoadProvider(macOpt->provider->providerPath, macOpt->provider->providerName);
    if (ret != HITLS_APP_SUCCESS) {
        (void)AppPrintError("Load provider failed\n");
        return NULL;
    }
    if (macOpt->provider->providerAttr == NULL) {
        macOpt->provider->providerAttr = "provider=default";
    }
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_ProviderMacNewCtx(APP_GetCurrent_Libctx(), macOpt->algId,
        macOpt->provider->providerAttr);  // creating an MAC Context
    if (ctx == NULL) {
        (void)AppPrintError("Failed to create the algorithm(%s) context\n", macOpt->algName);
        return NULL;
    }

    if (macOpt->key != NULL && macOpt->hexKey == NULL) {
        keyLen = strlen((const char*)macOpt->key);
        key = (uint8_t*)macOpt->key;
    } else if (macOpt->key == NULL && macOpt->hexKey != NULL) {
        uint32_t prefixLen = strlen(MAC_HEX_HEAD);
        if (strncmp((const char*)macOpt->hexKey, MAC_HEX_HEAD, prefixLen) != 0 || strlen((const char*)macOpt->hexKey) <= prefixLen) {
            AppPrintError("Invalid hexkey, should start with '0x'.\n");
            CRYPT_EAL_MacFreeCtx(ctx);
            return NULL;
        }

        ret = HexToByte(macOpt->hexKey + prefixLen, &key, &keyLen);
        if (ret == HITLS_APP_OPT_VALUE_INVALID) {
            AppPrintError("Invalid key: %s.\n", macOpt->hexKey);
            CRYPT_EAL_MacFreeCtx(ctx);
            return NULL;
        }
    } else {
        return NULL;
    }
    ret = CRYPT_EAL_MacInit(ctx, key, keyLen);
    if (ret != CRYPT_SUCCESS) {
        (void)AppPrintError("Summary context creation failed\n");
        CRYPT_EAL_MacFreeCtx(ctx);
        return NULL;
    }
    if (macOpt->key == NULL && macOpt->hexKey != NULL) {
        BSL_SAL_FREE(key);
    }
    return ctx;
}

static int32_t MacParamSet(CRYPT_EAL_MacCtx *ctx, MacOpt *macOpt)
{
    int32_t ret = HITLS_APP_SUCCESS;
    uint8_t *iv = NULL;
    uint32_t padding = CRYPT_PADDING_ZEROS;
    uint32_t ivLen = MAC_MAX_IV_LENGTH;

    if (macOpt->algId == CRYPT_MAC_CBC_MAC_SM4) {
        ret = CRYPT_EAL_MacCtrl(ctx, CRYPT_CTRL_SET_CBC_MAC_PADDING, &padding, sizeof(CRYPT_PaddingType));
        if (ret != CRYPT_SUCCESS) {
            (void)AppPrintError("Failed to set CBC MAC padding\n");
            return HITLS_APP_CRYPTO_FAIL;
        }
    }

    if (macOpt->iv != NULL) {
        ivLen = strlen((const char*)macOpt->iv);
        iv = (uint8_t *)macOpt->iv;
    }
    if (macOpt->hexIv != NULL) {
        uint32_t prefixLen = strlen(MAC_HEX_HEAD);
        if (strncmp((const char*)macOpt->hexIv, MAC_HEX_HEAD, prefixLen) != 0 || strlen((const char*)macOpt->hexIv) <= prefixLen) {
            AppPrintError("MAC: Invalid serial, should start with '0x'.\n");
            return HITLS_APP_OPT_VALUE_INVALID;
        }

        ret = HexToByte(macOpt->hexIv + prefixLen, &iv, &ivLen);
        if (ret == HITLS_APP_OPT_VALUE_INVALID) {
            AppPrintError("MAC: Invalid serial: %s.\n", macOpt->hexIv);
        }
    }

    if (macOpt->algId == CRYPT_MAC_GMAC_AES128 || macOpt->algId == CRYPT_MAC_GMAC_AES192||
        macOpt->algId == CRYPT_MAC_GMAC_AES256) {
        ret = CRYPT_EAL_MacCtrl(ctx, CRYPT_CTRL_SET_IV, macOpt->iv, ivLen);
        if (ret != CRYPT_SUCCESS) {
            (void)AppPrintError("Failed to set CBC MAC padding\n");
            return HITLS_APP_CRYPTO_FAIL;
        }
        ret = CRYPT_EAL_MacCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &(macOpt->tagLen), sizeof(int32_t));
        if (ret != CRYPT_SUCCESS) {
            (void)AppPrintError("Failed to set CBC MAC padding\n");
            return HITLS_APP_CRYPTO_FAIL;
        }
    }
    if (macOpt->iv == NULL && macOpt->hexIv != NULL) {
        BSL_SAL_FREE(iv);
    }
    return ret;
}

static int32_t MacValToFinal(MacOpt *macOpt, uint8_t *macBuf, uint32_t macBufLen,
    uint8_t **buf, uint32_t *bufLen, const char *filename)
{
    int32_t outRet = HITLS_APP_SUCCESS;
    uint32_t outBufLen;
    uint32_t hexBufLen = macBufLen * 9 + 1;
    uint8_t *hexBuf = (uint8_t *)BSL_SAL_Calloc(hexBufLen, sizeof(uint8_t));  // save the hexadecimal mac value
    if (hexBuf == NULL) {
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    if (macOpt->isBinary == 0) {
        outRet = HITLS_APP_OptToHex(macBuf, macBufLen, (char *)hexBuf, hexBufLen);
        if (outRet != HITLS_APP_SUCCESS) {
            BSL_SAL_FREE(hexBuf);
            return HITLS_APP_ENCODE_FAIL;
        }
    } else {
        outRet = HITLS_APP_OptToBin(macBuf, macBufLen, (char *)hexBuf, hexBufLen);
        if (outRet != HITLS_APP_SUCCESS) {
            BSL_SAL_FREE(hexBuf);
            return HITLS_APP_ENCODE_FAIL;
        }
    }

    if (macOpt->inFile == NULL) {
        // standard input(stdin) = macValue,
        // 5 indicates " " + "()" + "=" + "\n"
        outBufLen = strlen("stdin") + hexBufLen + 5;
    } else {
        // 5: " " + "()" + "=" + "\n", and concatenate the string alg_name(filename1)=mac.
        outBufLen = strlen((const char*)macOpt->algName) + strlen(filename) + hexBufLen + 5;
    }
    char *outBuf = (char *)BSL_SAL_Calloc(outBufLen, sizeof(char));  // save the concatenated mac value
    if (outBuf == NULL) {
        (void)AppPrintError("Failed to open the format control content space\n");
        BSL_SAL_FREE(hexBuf);
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    if (macOpt->inFile == NULL) {  // standard input
        outRet = snprintf_s(outBuf, outBufLen, outBufLen - 1, "(%s)= %s\n", "stdin", (char *)hexBuf);
    } else {
        outRet =
            snprintf_s(outBuf, outBufLen, outBufLen - 1, "%s(%s)= %s\n", macOpt->algName, filename, (char *)hexBuf);
    }

    uint32_t len = strlen(outBuf);
    BSL_SAL_FREE(hexBuf);
    if (outRet == -1) {
        BSL_SAL_FREE(outBuf);
        (void)AppPrintError("Failed to combine the output content\n");
        return HITLS_APP_SECUREC_FAIL;
    }
    char *finalOutBuf = (char *)BSL_SAL_Calloc(len, sizeof(char));
    if (memcpy_s(finalOutBuf, len, outBuf, strlen(outBuf)) != EOK) {
        BSL_SAL_FREE(outBuf);
        BSL_SAL_FREE(finalOutBuf);
        return HITLS_APP_SECUREC_FAIL;
    }
    BSL_SAL_FREE(outBuf);
    *buf = (uint8_t *)finalOutBuf;
    *bufLen = len;
    return HITLS_APP_SUCCESS;
}

static int32_t MacFinalToBuf(CRYPT_EAL_MacCtx *ctx, MacOpt *macOpt, uint8_t **buf, uint32_t *bufLen)
{
    int32_t outRet = HITLS_APP_SUCCESS;
    const char *filename = macOpt->inFile;
    if (filename == NULL) {
        filename = "stdin";
    }
    uint32_t macSize = CRYPT_EAL_GetMacLen(ctx);
    if (macSize <= 0) {
        return HITLS_APP_CRYPTO_FAIL;
    }
    uint8_t *macBuf = (uint8_t *)BSL_SAL_Calloc(macSize + 1, sizeof(uint8_t));
    if (macBuf == NULL) {
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    uint32_t macBufLen = macSize;
    outRet = CRYPT_EAL_MacFinal(ctx, macBuf, &macBufLen);  // complete the mac and output the final mac to the buf
    if (outRet != CRYPT_SUCCESS || macBufLen < macSize) {
        BSL_SAL_FREE(macBuf);
        (void)AppPrintError("filename: %s Failed to complete the final summary\n", filename);
        return HITLS_APP_CRYPTO_FAIL;
    }
    outRet = MacValToFinal(macOpt, macBuf, macBufLen, buf, bufLen, filename);
    BSL_SAL_FREE(macBuf);
    return outRet;
}

static int32_t BufOutToUio(const char *outFile, BSL_UIO *fileWriteUio, uint8_t *outBuf, uint32_t outBufLen)
{
    int32_t outRet = HITLS_APP_SUCCESS;
    if (outFile == NULL) {
        BSL_UIO *stdOutUio = HITLS_APP_UioOpen(NULL, 'w', 0);
        if (stdOutUio == NULL) {
            return HITLS_APP_UIO_FAIL;
        }
        outRet = HITLS_APP_OptWriteUio(stdOutUio, outBuf, outBufLen, HITLS_APP_FORMAT_TEXT);
        BSL_UIO_Free(stdOutUio);
        if (outRet != HITLS_APP_SUCCESS) {
            (void)AppPrintError("Failed to output the content to the screen\n");
            return HITLS_APP_UIO_FAIL;
        }
    } else {
        outRet = HITLS_APP_OptWriteUio(fileWriteUio, outBuf, outBufLen, HITLS_APP_FORMAT_TEXT);
        if (outRet != HITLS_APP_SUCCESS) {
            (void)AppPrintError("Failed to export data to the file path: <%s>\n", outFile);
            return HITLS_APP_UIO_FAIL;
        }
    }
    return HITLS_APP_SUCCESS;
}

static int32_t StdSumAndOut(CRYPT_EAL_MacCtx *ctx, MacOpt *macOpt)
{
    int32_t stdRet = HITLS_APP_SUCCESS;
    uint32_t readLen = MAX_BUFSIZE;
    uint8_t readBuf[MAX_BUFSIZE] = {0};
    bool isEof = false;
    uint8_t *outBuf = NULL;
    uint32_t outBufLen = 0;
    BSL_UIO *readUio = HITLS_APP_UioOpen(NULL, 'r', 1);
    if (readUio == NULL) {
        AppPrintError("Failed to open the stdin\n");
        return HITLS_APP_UIO_FAIL;
    }

    stdRet = MacParamSet(ctx, macOpt);
    if (stdRet != CRYPT_SUCCESS) {
        BSL_UIO_Free(readUio);
        (void)AppPrintError("Failed to set mac params\n");
        return HITLS_APP_CRYPTO_FAIL;
    }
    while (BSL_UIO_Ctrl(readUio, BSL_UIO_FILE_GET_EOF, IS_SUPPORT_GET_EOF, &isEof) == BSL_SUCCESS && !isEof) {
        if (BSL_UIO_Read(readUio, readBuf, MAX_BUFSIZE, &readLen) != BSL_SUCCESS) {
            BSL_UIO_Free(readUio);
            (void)AppPrintError("Failed to obtain the content from the STDIN\n");
            return HITLS_APP_STDIN_FAIL;
        }
        if (readLen == 0) {
            break;
        }

        stdRet = CRYPT_EAL_MacUpdate(ctx, readBuf, readLen);
        if (stdRet != CRYPT_SUCCESS) {
            BSL_UIO_Free(readUio);
            (void)AppPrintError("Failed to continuously summarize the STDIN content\n");
            return HITLS_APP_CRYPTO_FAIL;
        }
    }
    BSL_UIO_Free(readUio);

    // reads the final mac value to the buffer
    stdRet = MacFinalToBuf(ctx, macOpt, &outBuf, &outBufLen);
    if (stdRet != HITLS_APP_SUCCESS) {
        BSL_SAL_FREE(outBuf);
        return stdRet;
    }
    BSL_UIO *fileWriteUio = HITLS_APP_UioOpen(macOpt->outFile, 'w', 1);
    if (fileWriteUio == NULL) {
        BSL_UIO_SetIsUnderlyingClosedByUio(fileWriteUio, true);
        BSL_UIO_Free(fileWriteUio);
        BSL_SAL_FREE(outBuf);
        AppPrintError("Failed to open the <%s>\n", macOpt->outFile);
        return HITLS_APP_UIO_FAIL;
    }
    // outputs the mac value to the UIO
    stdRet = BufOutToUio(macOpt->outFile, fileWriteUio, (uint8_t *)outBuf, outBufLen);
    BSL_UIO_SetIsUnderlyingClosedByUio(fileWriteUio, true);
    BSL_UIO_Free(fileWriteUio);
    BSL_SAL_FREE(outBuf);
    return stdRet;
}

static int32_t ReadFileToBuf(CRYPT_EAL_MacCtx *ctx, MacOpt *macOpt)
{
    int32_t readRet = HITLS_APP_SUCCESS;
     const char *filename = macOpt->inFile;
    BSL_UIO *readUio = HITLS_APP_UioOpen(filename, 'r', 0);
    if (readUio == NULL) {
        (void)AppPrintError("Failed to open the file <%s>, No such file or directory\n", filename);
        return HITLS_APP_UIO_FAIL;
    }
    uint64_t readFileLen = 0;
    readRet = BSL_UIO_Ctrl(readUio, BSL_UIO_PENDING, sizeof(readFileLen), &readFileLen);
    if (readRet != BSL_SUCCESS) {
        BSL_UIO_SetIsUnderlyingClosedByUio(readUio, true);
        BSL_UIO_Free(readUio);
        (void)AppPrintError("Failed to obtain the content length\n");
        return HITLS_APP_UIO_FAIL;
    }

    readRet = MacParamSet(ctx, macOpt);
    if (readRet != CRYPT_SUCCESS) {
        BSL_UIO_Free(readUio);
        (void)AppPrintError("Failed to set mac params\n");
        return HITLS_APP_CRYPTO_FAIL;
    }

    while (readFileLen > 0) {
        uint8_t readBuf[MAX_BUFSIZE] = {0};
        uint32_t bufLen = (readFileLen > MAX_BUFSIZE) ? MAX_BUFSIZE : (uint32_t)readFileLen;
        uint32_t readLen = 0;
        readRet = BSL_UIO_Read(readUio, readBuf, bufLen, &readLen);  // read content to memory
        if (readRet != BSL_SUCCESS || bufLen != readLen) {
            BSL_UIO_SetIsUnderlyingClosedByUio(readUio, true);
            BSL_UIO_Free(readUio);
            (void)AppPrintError("Failed to read the input content\n");
            return HITLS_APP_UIO_FAIL;
        }
        readRet = CRYPT_EAL_MacUpdate(ctx, readBuf, bufLen);  // continuously enter summary content
        if (readRet != CRYPT_SUCCESS) {
            BSL_UIO_SetIsUnderlyingClosedByUio(readUio, true);
            BSL_UIO_Free(readUio);
            (void)AppPrintError("Failed to continuously summarize the file content\n");
            return HITLS_APP_CRYPTO_FAIL;
        }
        readFileLen -= bufLen;
    }
    BSL_UIO_SetIsUnderlyingClosedByUio(readUio, true);
    BSL_UIO_Free(readUio);
    return HITLS_APP_SUCCESS;
}

static int32_t FileSumOutStd(CRYPT_EAL_MacCtx *ctx, MacOpt *macOpt)
{
    int32_t outRet = HITLS_APP_SUCCESS;
    // Traverse the files that need to be maced, obtain the file content, calculate the file content mac,
    // and output the mac to the UIO.
    outRet = ReadFileToBuf(ctx, macOpt);  // read the file content by block and calculate the mac value
    if (outRet != HITLS_APP_SUCCESS) {
        return HITLS_APP_UIO_FAIL;
    }
    uint8_t *outBuf = NULL;
    uint32_t outBufLen = 0;
    outRet = MacFinalToBuf(ctx, macOpt, &outBuf, &outBufLen);  // read the final mac value to the buffer
    if (outRet != HITLS_APP_SUCCESS) {
        BSL_SAL_FREE(outBuf);
        (void)AppPrintError("Failed to output the final summary value\n");
        return outRet;
    }
    BSL_UIO *fileWriteUio = HITLS_APP_UioOpen(NULL, 'w', 0);  // the standard output is required for each file
    if (fileWriteUio == NULL) {
        BSL_SAL_FREE(outBuf);
        (void)AppPrintError("Failed to open the stdout\n");
        return HITLS_APP_UIO_FAIL;
    }
    outRet = BufOutToUio(NULL, fileWriteUio, (uint8_t *)outBuf, outBufLen);  // output the mac value to the UIO
    BSL_SAL_FREE(outBuf);
    BSL_UIO_Free(fileWriteUio);
    if (outRet != HITLS_APP_SUCCESS) {  // Released after the standard output is complete
        (void)AppPrintError("Failed to output the mac value\n");
        return outRet;
    }

    return HITLS_APP_SUCCESS;
}

static int32_t FileSumOutFile(CRYPT_EAL_MacCtx *ctx, MacOpt *macOpt)
{
    int32_t outRet = HITLS_APP_SUCCESS;
    const char *outFile = macOpt->outFile;
    BSL_UIO *fileWriteUio = HITLS_APP_UioOpen(outFile, 'w', 0);  // overwrite the original content
    if (fileWriteUio == NULL) {
        (void)AppPrintError("Failed to open the file path: %s\n", outFile);
        return HITLS_APP_UIO_FAIL;
    }
    BSL_UIO_SetIsUnderlyingClosedByUio(fileWriteUio, true);
    BSL_UIO_Free(fileWriteUio);
    fileWriteUio = HITLS_APP_UioOpen(outFile, 'a', 0);
    if (fileWriteUio == NULL) {
        (void)AppPrintError("Failed to open the file path: %s\n", outFile);
        return HITLS_APP_UIO_FAIL;
    }
    outRet = ReadFileToBuf(ctx, macOpt);  // read the file content by block and calculate the mac value
    if (outRet != HITLS_APP_SUCCESS) {
        BSL_UIO_SetIsUnderlyingClosedByUio(fileWriteUio, true);
        BSL_UIO_Free(fileWriteUio);
        (void)AppPrintError("Failed to read the file content by block and calculate the mac value\n");
        return HITLS_APP_UIO_FAIL;
    }
    uint8_t *outBuf = NULL;
    uint32_t outBufLen = 0;
    outRet = MacFinalToBuf(ctx, macOpt, &outBuf, &outBufLen);  // read the final mac value to the buffer
    if (outRet != HITLS_APP_SUCCESS) {
        BSL_SAL_FREE(outBuf);
        BSL_UIO_SetIsUnderlyingClosedByUio(fileWriteUio, true);
        BSL_UIO_Free(fileWriteUio);
        (void)AppPrintError("Failed to output the final summary value\n");
        return outRet;
    }
    outRet = BufOutToUio(outFile, fileWriteUio, (uint8_t *)outBuf, outBufLen);  // output the mac value to the UIO
    BSL_SAL_FREE(outBuf);
    if (outRet != HITLS_APP_SUCCESS) {
        BSL_UIO_SetIsUnderlyingClosedByUio(fileWriteUio, true);
        BSL_UIO_Free(fileWriteUio);
        return outRet;
    }

    BSL_UIO_SetIsUnderlyingClosedByUio(fileWriteUio, true);
    BSL_UIO_Free(fileWriteUio);
    return HITLS_APP_SUCCESS;
}

static int32_t FileSumAndOut(CRYPT_EAL_MacCtx *ctx, MacOpt *macOpt)
{
    int32_t outRet = HITLS_APP_SUCCESS;
    if (macOpt->outFile == NULL) {
        // standard output, w overwriting mode
        outRet = FileSumOutStd(ctx, macOpt);
    } else {
        // file output appending mode
        outRet = FileSumOutFile(ctx, macOpt);
    }
    return outRet;
}

int32_t HITLS_MacMain(int argc, char *argv[])
{
    int32_t mainRet = HITLS_APP_SUCCESS;
    AppProvider appProvider = {NULL, NULL, NULL};
    MacOpt macOpt = {
        NULL, CRYPT_MAC_HMAC_SHA256, 0, 0, NULL, NULL, NULL, NULL, 0, NULL, NULL, 0, &appProvider};
    CRYPT_EAL_MacCtx *ctx = NULL;
    mainRet = HITLS_APP_OptBegin(argc, argv, g_macOpts);
    if (mainRet != HITLS_APP_SUCCESS) {
        (void)AppPrintError("error in opt begin.\n");
        goto end;
    }
    mainRet = HandleOpt(&macOpt);
    if (mainRet != HITLS_APP_SUCCESS) {
        goto end;
    }
    mainRet = CheckParam(&macOpt);
    if (mainRet != HITLS_APP_SUCCESS) {
        goto end;
    }
    ctx = InitAlgMac(&macOpt);
    if (ctx == NULL) {
        mainRet = HITLS_APP_CRYPTO_FAIL;
        goto end;
    }

    mainRet = (macOpt.inFile == NULL) ? StdSumAndOut(ctx, &macOpt) : FileSumAndOut(ctx, &macOpt);
    CRYPT_EAL_MacDeinit(ctx);  // algorithm release
end:
    CRYPT_EAL_MacFreeCtx(ctx);
    HITLS_APP_OptEnd();
    return mainRet;
}
