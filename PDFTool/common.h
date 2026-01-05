#ifndef COMMON_H
#define COMMON_H

#include <QStringList>

enum {
    JS_FILE_TYPE_CERT,
    JS_FILE_TYPE_CRL,
    JS_FILE_TYPE_CSR,
    JS_FILE_TYPE_PRIKEY,
    JS_FILE_TYPE_TXT,
    JS_FILE_TYPE_BER,
    JS_FILE_TYPE_CFG,
    JS_FILE_TYPE_PFX,
    JS_FILE_TYPE_BIN,
    JS_FILE_TYPE_DLL,
    JS_FILE_TYPE_LCN,
    JS_FILE_TYPE_JSON,
    JS_FILE_TYPE_PKCS7,
    JS_FILE_TYPE_PKCS8,
    JS_FILE_TYPE_PRIKEY_PKCS8_PFX,
    JS_FILE_TYPE_DH_PARAM,
    JS_FILE_TYPE_PDF,
    JS_FILE_TYPE_ALL };

const QString kEnvMiscGroup = "Misc";
const QString kEnvTempGroup = "Temp";

#endif // COMMON_H
