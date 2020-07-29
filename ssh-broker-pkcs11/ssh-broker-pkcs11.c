#include <assert.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <pkcs11.h>
#include <json-c/json.h>
#include "ssh_broker_client.h"

static_assert(sizeof(CK_SESSION_HANDLE) >= sizeof(void*), "Session handles are not big enough to hold a pointer to the session struct on this architecture");
static_assert(sizeof(CK_OBJECT_HANDLE) >= sizeof(void*), "Object handles are not big enough to hold a pointer to the session struct on this architecture");

static json_object* config = NULL;
static SshBrokerClient* ssh_broker_client = NULL;

// Returns the configuration value for the given key. The returned string does not need to be freed as it is owned by
// the configuration instance. However, any strings returned will be freed when C_Finalize is called, so if something
// needs to live longer than that, make sure to use strdup(). Will return NULL if no config value is set for the key.
static const char* get_config(const char* key) {
    if (config == NULL || !json_object_is_type(config, json_type_object)) {
        return NULL;
    }
    struct json_object* val;
    if (json_object_object_get_ex(config, key, &val) && json_object_is_type(val, json_type_string)) {
        return json_object_get_string(val);
    }
    return NULL;
}

static CK_RV load_config() {
    CK_RV res = CKR_OK;
    char* paths[2];
    paths[0] = "/etc/ssh-broker-pkcs11/config.json";
    paths[1] = NULL;

    char* xdg_config_home = getenv("XDG_CONFIG_HOME");
    CK_BBOOL free_xdg_config_home = CK_FALSE;
    if (xdg_config_home == NULL) {
        char* home = getenv("HOME");
        if (home != NULL) {
            size_t len = strlen(home) + strlen("/.config");
            xdg_config_home = malloc(len+1);
            if (xdg_config_home == NULL) {
                res = CKR_HOST_MEMORY;
                goto cleanup;
            }
            free_xdg_config_home = CK_TRUE;
            snprintf(xdg_config_home, len+1, "%s/.config", home);
        }
    }
    if (xdg_config_home == NULL) {
        paths[1] = NULL;
    } else {
        size_t len = strlen(xdg_config_home) + strlen("/ssh-broker-pkcs11/config.json");
        paths[1] = malloc(len+1);
        if (paths[1] == NULL) {
            res = CKR_HOST_MEMORY;
            goto cleanup;
        }
        snprintf(paths[1], len+1, "%s/ssh-broker-pkcs11/config.json", xdg_config_home);
        if (free_xdg_config_home && xdg_config_home != NULL) {
            free(xdg_config_home);
        }
    }

    config = json_object_new_object();
    for (size_t i = 0; i < sizeof(paths)/sizeof(char*); i++) {
        if (paths[i] == NULL) {
            continue;
        }
        FILE* f = fopen(paths[i], "r");
        if (f == NULL) {
            continue;
        }

        fseek(f, 0L, SEEK_END);
        size_t file_size = ftell(f);
        fseek(f, 0L, SEEK_SET);

        char* buffer = malloc(file_size);
        if (buffer == NULL) {
            fclose(f);
            res = CKR_HOST_MEMORY;
            goto cleanup;
        }

        size_t actual = fread(buffer, file_size, 1, f);
        fclose(f);
        if (actual != 1) {
            res = CKR_FUNCTION_FAILED;
            goto cleanup;
        }

        struct json_tokener* tok = json_tokener_new();
        struct json_object* conf = json_tokener_parse_ex(tok, buffer, file_size);
        json_tokener_free(tok);

        if (conf != NULL) {
            if (json_object_is_type(conf, json_type_object)) {
                json_object_object_foreach(conf, key, val) {
                    if (json_object_is_type(val, json_type_string)) {
                        json_object_object_add(config, key, json_object_new_string(json_object_get_string(val)));
                    }
                }
            }
            json_object_put(conf);
        }
    }

cleanup:
    if (free_xdg_config_home && xdg_config_home != NULL) {
        free(xdg_config_home);
    }
    if (paths[1] != NULL) {
        free(paths[1]);
    }
    if (config != NULL && res != CKR_OK) {
        json_object_put(config);
        config = NULL;
    }
    return res;
}

typedef struct _session {
    CK_ATTRIBUTE_PTR find_objects_template;
    CK_ULONG find_objects_template_count;
    unsigned long find_objects_index;
    ListKeysResponse* key_data;

    unsigned long sign_key_index;
    CK_MECHANISM_TYPE sign_mechanism;
} CkSession;

CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
    CK_RV res = load_config();
    if (res != CKR_OK) {
        return res;
    }

    ssh_broker_client = SshBrokerClient_new();
    const char* val;
    if ((val = get_config("hostname")) != NULL) {
        ssh_broker_client->hostname = strdup(val);
    } else {
        C_Finalize(NULL_PTR);
        return CKR_ARGUMENTS_BAD;
    }
    if ((val = get_config("capath")) != NULL) {
        ssh_broker_client->capath = strdup(val);
    }
    if ((val = get_config("client_cert_path")) != NULL) {
        ssh_broker_client->client_cert_path = strdup(val);
    }
    if ((val = get_config("client_key_path")) != NULL) {
        ssh_broker_client->client_key_path = strdup(val);
    }

    return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved) {
    if (ssh_broker_client != NULL) {
        SshBrokerClient_free(ssh_broker_client);
        ssh_broker_client = NULL;
    }
    if (config != NULL) {
        json_object_put(config);
        config = NULL;
    }
    return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo) {
    if (pInfo == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }
    memset(pInfo, 0, sizeof(*pInfo));
    pInfo->cryptokiVersion.major = 2;
    pInfo->cryptokiVersion.minor = 4;
    return CKR_OK;
}

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {
    if (pulCount == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }
    if (pSlotList != NULL_PTR) {
        if (*pulCount == 0) {
            return CKR_BUFFER_TOO_SMALL;
        }
        pSlotList[0] = 0;
    } else {
        *pulCount = 1;
    }
    return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
    if (slotID != 0) {
        return CKR_SLOT_ID_INVALID;
    }
    if (pInfo == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    memset(pInfo, 0, sizeof(*pInfo));
    return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {
    if (slotID != 0) {
        return CKR_SLOT_ID_INVALID;
    }
    if (pInfo == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    memset(pInfo, 0, sizeof(*pInfo));
    pInfo->flags = CKF_TOKEN_INITIALIZED;
    return CKR_OK;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
    return CKR_OK;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession) {
    return CKR_OK;
}

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY notify, CK_SESSION_HANDLE_PTR phSession) {
    if (slotID != 0) {
        return CKR_SLOT_ID_INVALID;
    }

    CkSession* session = malloc(sizeof(CkSession));
    if (session == NULL) {
        return CKR_HOST_MEMORY;
    }
    session->key_data = ssh_broker_list_keys(ssh_broker_client);

    *phSession = (CK_SESSION_HANDLE)session;
    return CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
    CkSession *session = (CkSession*)hSession;
    if (session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    ListKeysResponse_free(session->key_data);
    free(session);
    return CKR_OK;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID) {
    // Not supported
    return CKR_FUNCTION_FAILED;
}

CK_RV getAttributeValue(RemoteKey* key, CK_ATTRIBUTE_TYPE attr, CK_VOID_PTR pValue, CK_ULONG_PTR pulValueLen) {

    const unsigned char* pubkey_bytes = key->public_key;
    unsigned char* buffer, *buffer2;
    EVP_PKEY* pkey;
    const RSA* rsa;
    const EC_KEY* ec_key;
    const EC_GROUP* ec_group;
    const BIGNUM* bn;
    size_t len, len2;

    switch (attr) {
        case CKA_CLASS:
            *pulValueLen = sizeof(CK_OBJECT_CLASS);
            if (pValue != NULL_PTR) {
                *((CK_OBJECT_CLASS*)pValue) = CKO_PRIVATE_KEY;
            }
            break;
        case CKA_ID:
            *pulValueLen = key->public_key_length;
            if (pValue != NULL_PTR) {
                memcpy(pValue, key->public_key, key->public_key_length);
            }
            break;
        case CKA_SIGN:
            *pulValueLen = sizeof(CK_BBOOL);
            if (pValue != NULL_PTR) {
                *((CK_BBOOL*)pValue) = CK_TRUE;
            }
            break;
        case CKA_KEY_TYPE:
            pkey = d2i_PUBKEY(NULL, &pubkey_bytes, key->public_key_length);
            if (pkey == NULL) {
                return CKR_FUNCTION_FAILED;
            }

            CK_OBJECT_CLASS key_type;
            switch (EVP_PKEY_base_id(pkey)) {
                case EVP_PKEY_RSA:
                    key_type = CKK_RSA;
                    break;
                case EVP_PKEY_EC:
                    key_type = CKK_ECDSA;
                    break;
                default:
                    EVP_PKEY_free(pkey);
                    return CKR_ATTRIBUTE_TYPE_INVALID;
            }

            *pulValueLen = sizeof(CK_OBJECT_CLASS);
            if (pValue != NULL_PTR) {
                *((CK_OBJECT_CLASS*)pValue) = key_type;
            }
            break;
        case CKA_ALWAYS_AUTHENTICATE:
            *pulValueLen = sizeof(CK_BBOOL);
            if (pValue != NULL_PTR) {
                *((CK_BBOOL*)pValue) = CK_FALSE;
            }
            break;
        case CKA_LABEL:
            *pulValueLen = strlen(key->key_name);
            if (pValue != NULL_PTR) {
                memcpy(pValue, key->key_name, *pulValueLen);
            }
            break;
        case CKA_MODULUS:
            pkey = d2i_PUBKEY(NULL, &pubkey_bytes, key->public_key_length);
            if (pkey == NULL) {
                return CKR_FUNCTION_FAILED;
            }
            if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
                EVP_PKEY_free(pkey);
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }
            rsa = EVP_PKEY_get0_RSA(pkey);
            bn = RSA_get0_n(rsa);

            *pulValueLen = BN_num_bytes(bn);
            if (pValue != NULL_PTR) {
                BN_bn2bin(bn, pValue);
            }
            break;
        case CKA_PUBLIC_EXPONENT:
            pkey = d2i_PUBKEY(NULL, &pubkey_bytes, key->public_key_length);
            if (pkey == NULL) {
                return CKR_FUNCTION_FAILED;
            }
            if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
                EVP_PKEY_free(pkey);
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }
            rsa = EVP_PKEY_get0_RSA(pkey);
            bn = RSA_get0_e(rsa);

            *pulValueLen = BN_num_bytes(bn);
            if (pValue != NULL_PTR) {
                BN_bn2bin(bn, pValue);
            }
            break;
        case CKA_EC_POINT:
            pkey = d2i_PUBKEY(NULL, &pubkey_bytes, key->public_key_length);
            if (pkey == NULL) {
                return CKR_FUNCTION_FAILED;
            }
            if (EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) {
                EVP_PKEY_free(pkey);
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }
            ec_key = EVP_PKEY_get0_EC_KEY(pkey);

            buffer = NULL;
            len = i2o_ECPublicKey(ec_key, &buffer);

            // Wrap the point in an ASN.1 octet string
            ASN1_OCTET_STRING* os = ASN1_STRING_new();
            ASN1_OCTET_STRING_set(os, buffer, len);

            buffer2 = NULL;
            len2 = i2d_ASN1_OCTET_STRING(os, &buffer2);

            *pulValueLen = len2;
            if (pValue != NULL_PTR) {
                memcpy(pValue, buffer2, len2);
            }

            free(buffer);
            free(buffer2);
            EVP_PKEY_free(pkey);
            break;
        case CKA_EC_PARAMS:
            pkey = d2i_PUBKEY(NULL, &pubkey_bytes, key->public_key_length);
            if (pkey == NULL) {
                return CKR_FUNCTION_FAILED;
            }
            if (EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) {
                EVP_PKEY_free(pkey);
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }
            ec_key = EVP_PKEY_get0_EC_KEY(pkey);
            ec_group = EC_KEY_get0_group(ec_key);

            buffer = NULL;
            len = i2d_ECPKParameters(ec_group, &buffer);

            *pulValueLen = len;
            if (pValue != NULL_PTR) {
                memcpy(pValue, buffer, len);
            }

            free(buffer);
            EVP_PKEY_free(pkey);
            break;
        default:
            return CKR_ATTRIBUTE_TYPE_INVALID;
    }

    return CKR_OK;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
    CkSession *session = (CkSession*)hSession;
    if (session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    session->find_objects_template = malloc(sizeof(CK_ATTRIBUTE) * ulCount);
    for (CK_ULONG i = 0; i < ulCount; i++) {
        session->find_objects_template[i].type = pTemplate[i].type;
        session->find_objects_template[i].pValue = malloc(pTemplate[i].ulValueLen);
        memcpy(session->find_objects_template[i].pValue, pTemplate[i].pValue, pTemplate[i].ulValueLen);
        session->find_objects_template[i].ulValueLen = pTemplate[i].ulValueLen;
    }
    session->find_objects_template_count = ulCount;
    session->find_objects_index = 0;

    return CKR_OK;
}

static CK_BBOOL matches_template(CkSession* session, RemoteKey* key) {
    unsigned char* buffer = NULL;
    CK_ULONG buffer_size = 0;
    CK_RV res;

    for (CK_ULONG i = 0; i < session->find_objects_template_count; i++) {
        CK_ATTRIBUTE attr = session->find_objects_template[i];

        // Special case for CKA_CLASS because we want to match CKO_PUBLIC_KEY even though we have a CKO_PRIVATE_KEY
        if (attr.type == CKA_CLASS) {
            CK_OBJECT_CLASS clazz = *((CK_OBJECT_CLASS*)attr.pValue);
            if (clazz != CKO_PUBLIC_KEY && clazz != CKO_PRIVATE_KEY) {
                return CK_FALSE;
            }
            continue;
        }

        // Otherwise pull the real attribute value and check for a byte-array-equality on the value.
        res = getAttributeValue(key, attr.type, NULL_PTR, &buffer_size);
        if (res != CKR_OK) {
            return res;
        }
        if (buffer_size != attr.ulValueLen) {
            return CK_FALSE;
        }
        buffer = malloc(buffer_size);
        if (buffer == NULL) {
            return CKR_HOST_MEMORY;
        }
        res = getAttributeValue(key, attr.type, buffer, &buffer_size);
        if (res != CKR_OK) {
            return res;
        }
        if (memcmp(buffer, attr.pValue, buffer_size) != 0) {
            return CK_FALSE;
        }
    }
    return CK_TRUE;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount) {
    CkSession *session = (CkSession*)hSession;
    if (session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (session->key_data == NULL) {
        *pulObjectCount = 0;
        return CKR_OK;
    }

    unsigned long foundObjects = 0;
    while (foundObjects < ulMaxObjectCount && session->find_objects_index < session->key_data->keys_length) {
        if (matches_template(session, session->key_data->keys[session->find_objects_index])) {
            phObject[foundObjects] = session->find_objects_index;
            foundObjects += 1;
        }
        session->find_objects_index += 1;
    }

    *pulObjectCount = foundObjects;
    return CKR_OK;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession) {
    CkSession *session = (CkSession*)hSession;
    if (session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    for (CK_ULONG i = 0; i < session->find_objects_template_count; i++) {
        free(session->find_objects_template[i].pValue);
    }
    free(session->find_objects_template);

    session->find_objects_template = NULL;
    session->find_objects_template_count = 0;
    session->find_objects_index = 0;
    return CKR_OK;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
    CkSession *session = (CkSession*)hSession;
    if (session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (pTemplate == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    if (session->key_data == NULL || hObject >= session->key_data->keys_length) {
        return CKR_OBJECT_HANDLE_INVALID;
    }
    RemoteKey* key = session->key_data->keys[hObject];

    for (CK_ULONG i = 0; i < ulCount; i++) {
        CK_RV res = getAttributeValue(key, pTemplate[i].type, pTemplate[i].pValue, &pTemplate[i].ulValueLen);
        if (res != CKR_OK) {
            return res;
        }
    }
    return CKR_OK;
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    CkSession *session = (CkSession*)hSession;
    if (session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (pMechanism == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }
    if (session->key_data == NULL || hKey >= session->key_data->keys_length) {
        return CKR_OBJECT_HANDLE_INVALID;
    }
    session->sign_key_index = hKey;
    session->sign_mechanism = pMechanism->mechanism;

    return CKR_OK;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
    return CKR_OK;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
    *pulSignatureLen = 0;
    return CKR_OK;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
    CkSession *session = (CkSession*)hSession;
    if (session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (pData == NULL_PTR || pulSignatureLen == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    RemoteKey* key = session->key_data->keys[session->sign_key_index];

    size_t sig_size;
    const unsigned char* pubkey_const = key->public_key;
    EVP_PKEY* pkey = d2i_PUBKEY(NULL, &pubkey_const, key->public_key_length);
    const EC_KEY* ec_key;
    const RSA* rsa;

    int key_type = EVP_PKEY_base_id(pkey);
    switch (key_type) {
        case EVP_PKEY_RSA:
            rsa = EVP_PKEY_get0_RSA(pkey);
            sig_size = BN_num_bytes(RSA_get0_n(rsa));
            break;
        case EVP_PKEY_EC:
            ec_key = EVP_PKEY_get0_EC_KEY(pkey);
            sig_size = ECDSA_size(ec_key);
            break;
        default:
            EVP_PKEY_free(pkey);
            return CKR_FUNCTION_FAILED;

    }
    EVP_PKEY_free(pkey);
    pkey = NULL;

    if (pSignature == NULL_PTR) {
        *pulSignatureLen = sig_size;
        return CKR_OK;
    }

    SignatureAlgorithm signature_algorithm;
    switch (session->sign_mechanism) {
        case CKM_ECDSA:
            signature_algorithm = NONE_WITH_ECDSA;
            break;
        case CKM_RSA_PKCS:
            signature_algorithm = NONE_WITH_RSA;
            break;
        default:
            return CKR_ARGUMENTS_BAD;
    }

    unsigned char* sigData;
    size_t sigLen;
    ssh_broker_sign(ssh_broker_client, signature_algorithm,
        key->public_key, key->public_key_length, pData, ulDataLen, &sigData, &sigLen);

    const unsigned char* sigDataConst = sigData;

    if (key_type == EVP_PKEY_EC) {
        ECDSA_SIG* sig = d2i_ECDSA_SIG(NULL, &sigDataConst, sigLen);
        if (sig == NULL) {
            return CKR_FUNCTION_FAILED;
        }
        const BIGNUM* r = ECDSA_SIG_get0_r(sig);
        const BIGNUM* s = ECDSA_SIG_get0_s(sig);

        if (BN_num_bytes(r) + BN_num_bytes(s) > sig_size) {
            return CKR_FUNCTION_FAILED;
        }
        int pos = BN_bn2bin(r, pSignature);
        pos += BN_bn2bin(s, pSignature + pos);
        *pulSignatureLen = pos;
        ECDSA_SIG_free(sig);
    } else {
        if (sigLen > sig_size) {
            return CKR_FUNCTION_FAILED;
        }
        memcpy(pSignature, sigData, sigLen);
        *pulSignatureLen = sigLen;
    }

    return CKR_OK;
}

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
    static CK_FUNCTION_LIST function_list = {
               version: {
                   major: 0,
                   minor: 0
               },
               C_Initialize: C_Initialize,
               C_Finalize: C_Finalize,
               C_GetInfo: C_GetInfo,
               C_GetFunctionList: C_GetFunctionList,
               C_GetSlotList: C_GetSlotList,
               C_GetSlotInfo: C_GetSlotInfo,
               C_GetTokenInfo: C_GetTokenInfo,
               C_GetMechanismList: NULL_PTR,
               C_GetMechanismInfo: NULL_PTR,
               C_InitToken: NULL_PTR,
               C_InitPIN: NULL_PTR,
               C_SetPIN: NULL_PTR,
               C_OpenSession: C_OpenSession,
               C_CloseSession: C_CloseSession,
               C_CloseAllSessions: C_CloseAllSessions,
               C_GetSessionInfo: NULL_PTR,
               C_GetOperationState: NULL_PTR,
               C_SetOperationState: NULL_PTR,
               C_Login: C_Login,
               C_Logout: C_Logout,
               C_CreateObject: NULL_PTR,
               C_CopyObject: NULL_PTR,
               C_DestroyObject: NULL_PTR,
               C_GetObjectSize: NULL_PTR,
               C_GetAttributeValue: C_GetAttributeValue,
               C_SetAttributeValue: NULL_PTR,
               C_FindObjectsInit: C_FindObjectsInit,
               C_FindObjects: C_FindObjects,
               C_FindObjectsFinal: C_FindObjectsFinal,
               C_EncryptInit: NULL_PTR,
               C_Encrypt: NULL_PTR,
               C_EncryptUpdate: NULL_PTR,
               C_EncryptFinal: NULL_PTR,
               C_DecryptInit: NULL_PTR,
               C_Decrypt: NULL_PTR,
               C_DecryptUpdate: NULL_PTR,
               C_DecryptFinal: NULL_PTR,
               C_DigestInit: NULL_PTR,
               C_Digest: NULL_PTR,
               C_DigestUpdate: NULL_PTR,
               C_DigestKey: NULL_PTR,
               C_DigestFinal: NULL_PTR,
               C_SignInit: C_SignInit,
               C_Sign: C_Sign,
               C_SignUpdate: C_SignUpdate,
               C_SignFinal: C_SignFinal,
               C_SignRecoverInit: NULL_PTR,
               C_SignRecover: NULL_PTR,
               C_VerifyInit: NULL_PTR,
               C_Verify: NULL_PTR,
               C_VerifyUpdate: NULL_PTR,
               C_VerifyFinal: NULL_PTR,
               C_VerifyRecoverInit: NULL_PTR,
               C_VerifyRecover: NULL_PTR,
               C_DigestEncryptUpdate: NULL_PTR,
               C_DecryptDigestUpdate: NULL_PTR,
               C_SignEncryptUpdate: NULL_PTR,
               C_DecryptVerifyUpdate: NULL_PTR,
               C_GenerateKey: NULL_PTR,
               C_GenerateKeyPair: NULL_PTR,
               C_WrapKey: NULL_PTR,
               C_UnwrapKey: NULL_PTR,
               C_DeriveKey: NULL_PTR,
               C_SeedRandom: NULL_PTR,
               C_GenerateRandom: NULL_PTR,
               C_GetFunctionStatus: NULL_PTR,
               C_CancelFunction: NULL_PTR,
               C_WaitForSlotEvent: NULL_PTR,
           };

    if (ppFunctionList == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    *ppFunctionList = &function_list;
    return CKR_OK;
}

