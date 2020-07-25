#include <assert.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <pkcs11.h>

static_assert(sizeof(CK_SESSION_HANDLE) >= sizeof(void*), "Session handles are not big enough to hold a pointer to the session struct on this architecture");
static_assert(sizeof(CK_OBJECT_HANDLE) >= sizeof(void*), "Object handles are not big enough to hold a pointer to the session struct on this architecture");

const unsigned char PRIVATE_KEY_PKCS8[] = {
  0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
  0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
  0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02, 0x01, 0x01, 0x04, 0x20,
  0x34, 0x8e, 0x05, 0x25, 0x85, 0x28, 0x6b, 0xac, 0x46, 0xda, 0x89, 0x65,
  0xb3, 0x84, 0x3a, 0xd5, 0x07, 0xa4, 0x5d, 0x67, 0x24, 0xbb, 0xa6, 0x5c,
  0x47, 0xa1, 0xb9, 0x5f, 0x26, 0x0e, 0x1c, 0xc0, 0xa1, 0x44, 0x03, 0x42,
  0x00, 0x04, 0xba, 0x92, 0x07, 0xe1, 0xbe, 0x69, 0x91, 0x7f, 0x17, 0x30,
  0x30, 0x16, 0xd3, 0xa2, 0x34, 0x2e, 0xaf, 0xe0, 0xdf, 0xd4, 0x3f, 0x60,
  0x78, 0x38, 0x55, 0x3a, 0x84, 0xea, 0xd3, 0xd1, 0x63, 0x41, 0xd9, 0x4b,
  0x4e, 0xa6, 0x65, 0x67, 0x97, 0xd6, 0x5d, 0xf5, 0x05, 0x8e, 0x43, 0x1f,
  0xec, 0xbb, 0xbf, 0x53, 0xe0, 0x35, 0xbe, 0xc1, 0x2b, 0x1d, 0xcf, 0x12,
  0x57, 0x1c, 0x9a, 0x9d, 0x45, 0xf1
};

typedef struct _session {
    CK_ATTRIBUTE_PTR find_objects_template;
    CK_ULONG find_objects_template_count;
    unsigned long find_objects_index;
} CkSession;

EVP_PKEY* private_key = NULL;

CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
    if (private_key == NULL) {
        const unsigned char* buffer = (const unsigned char*)PRIVATE_KEY_PKCS8;
        private_key = d2i_AutoPrivateKey(NULL, &buffer, sizeof(PRIVATE_KEY_PKCS8));
        if (private_key == NULL) {
            return CKR_FUNCTION_FAILED;
        }
    }

    return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved) {
    if (private_key != NULL) {
        EVP_PKEY_free(private_key);
        private_key = NULL;
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

    *phSession = (CK_SESSION_HANDLE)session;
    return CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
    CkSession *session = (CkSession*)hSession;
    if (session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    free(session);
    return CKR_OK;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID) {
    // Not supported
    return CKR_FUNCTION_FAILED;
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

static CK_BBOOL matches_template(CkSession* session, CK_ULONG objIndex) {
    CK_OBJECT_CLASS clazz;
    for (CK_ULONG i = 0; i < session->find_objects_template_count; i++) {
        CK_ATTRIBUTE attr = session->find_objects_template[i];
        switch (attr.type) {
            case CKA_CLASS:
                clazz = *((CK_OBJECT_CLASS*)attr.pValue);
                if (clazz != CKO_PRIVATE_KEY && clazz != CKO_PUBLIC_KEY) {
                    return CK_FALSE;
                }
                break;
            case CKA_ID:
                // We don't actually use this right now, so always match whatever ID is passed in
                break;
            case CKA_SIGN:
                // All objects allow signing
                if (*((CK_BBOOL*)attr.pValue) == CK_FALSE) {
                    return CK_FALSE;
                }
            default:
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

    unsigned long foundObjects = 0;
    while (foundObjects < ulMaxObjectCount && session->find_objects_index < 1) {
        if (matches_template(session, session->find_objects_index)) {
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
    unsigned char *buffer, *buffer2;
    int len, len2;
    const EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(private_key);
    const EC_GROUP* group = EC_KEY_get0_group(ec_key);

    CkSession *session = (CkSession*)hSession;
    if (session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (hObject != 0) {
        return CKR_OBJECT_HANDLE_INVALID;
    }
    if (pTemplate == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }
    for (CK_ULONG i = 0; i < ulCount; i++) {
        switch (pTemplate[i].type) {
            case CKA_KEY_TYPE:
                if (pTemplate[i].pValue != NULL_PTR) {
                    if (pTemplate[i].ulValueLen < sizeof(CK_OBJECT_CLASS)) {
                        return CKR_BUFFER_TOO_SMALL;
                    }
                    *((CK_OBJECT_CLASS_PTR)pTemplate[i].pValue) = CKK_ECDSA;
                }
                pTemplate[i].ulValueLen = sizeof(CK_OBJECT_CLASS);
                break;
            case CKA_ALWAYS_AUTHENTICATE:
                if (pTemplate[i].pValue != NULL_PTR) {
                    if (pTemplate[i].ulValueLen < sizeof(CK_BBOOL)) {
                        return CKR_BUFFER_TOO_SMALL;
                    }
                    *((CK_OBJECT_CLASS_PTR)pTemplate[i].pValue) = CK_FALSE;
                }
                pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                break;
            case CKA_LABEL:
                pTemplate[i].ulValueLen = 4;
                if (pTemplate[i].pValue != NULL_PTR) {
                    memcpy(pTemplate[i].pValue, "derp", 4);
                }
                break;
            case CKA_ID:
                pTemplate[i].ulValueLen = 4;
                if (pTemplate[i].pValue != NULL_PTR) {
                    memcpy(pTemplate[i].pValue, "derp", 4);
                }
                break;
            case CKA_EC_POINT:
                buffer = NULL;
                len = i2o_ECPublicKey(ec_key, &buffer);

                // Wrap the point in an ASN.1 octet string
                ASN1_OCTET_STRING* os = ASN1_STRING_new();
                ASN1_OCTET_STRING_set(os, buffer, len);

                buffer2 = NULL;
                len2 = i2d_ASN1_OCTET_STRING(os, &buffer2);

                if (pTemplate[i].pValue != NULL_PTR) {
                    if (pTemplate[i].ulValueLen < len2) {
                        free(buffer);
                        free(buffer2);
                        return CKR_BUFFER_TOO_SMALL;
                    }
                    memcpy(pTemplate[i].pValue, buffer2, len2);
                }
                free(buffer);
                free(buffer2);
                pTemplate[i].ulValueLen = len2;
                break;
            case CKA_EC_PARAMS:
                buffer = NULL;
                len = i2d_ECPKParameters(group, &buffer);
                if (pTemplate[i].pValue != NULL_PTR) {
                    if (pTemplate[i].ulValueLen < len) {
                        free(buffer);
                        return CKR_BUFFER_TOO_SMALL;
                    }
                    memcpy(pTemplate[i].pValue, buffer, len);
                }
                free(buffer);
                pTemplate[i].ulValueLen = len;
                break;
            default:
                return CKR_ATTRIBUTE_TYPE_INVALID;
        }
    }

    return CKR_OK;
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
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
    EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(private_key);
    unsigned int siglen = ECDSA_size(ec_key);
    if (pSignature == NULL_PTR) {
        *pulSignatureLen = siglen;
        return CKR_OK;
    }

    if (*pulSignatureLen < siglen) {
        return CKR_BUFFER_TOO_SMALL;
    }

    ECDSA_SIG* sig = ECDSA_do_sign(pData, ulDataLen, ec_key);
    if (sig == NULL) {
        return CKR_FUNCTION_FAILED;
    }
    const BIGNUM* r = ECDSA_SIG_get0_r(sig);
    const BIGNUM* s = ECDSA_SIG_get0_s(sig);

    assert(BN_num_bytes(r) + BN_num_bytes(s) <= siglen);
    int pos = BN_bn2bin(r, pSignature);
    pos += BN_bn2bin(s, pSignature + pos);

    ECDSA_SIG_free(sig);

    *pulSignatureLen = pos;
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

