#include <stdio.h>
#include <stdlib.h>
#include <pkcs11.h>

void dump_bytes(const char* name, const unsigned char* bytes, unsigned long len) {
    printf("%s=", name);
    for (unsigned long i = 0; i < len; i++) {
        printf("%.2X ", bytes[i]);
    }
    printf("\n");
}

CK_RV get_and_dump_attribute(CK_SESSION_HANDLE session, CK_ATTRIBUTE_TYPE type, const char* name) {
    CK_ATTRIBUTE attrs[1];
    attrs[0].type = type;
    attrs[0].pValue = NULL;
    attrs[0].ulValueLen = 0;
    CK_RV res = C_GetAttributeValue(session, (CK_OBJECT_HANDLE)0, attrs, 1);
    if (res != CKR_OK) {
        printf("Fail C_GetAttributeValue for attribute size, res=%ld\n", res);
        return res;
    }
    attrs[0].pValue = malloc(attrs[0].ulValueLen);
    res = C_GetAttributeValue(session, (CK_OBJECT_HANDLE)0, attrs, 1);
    if (res != CKR_OK) {
        printf("Fail C_GetAttributeValue for getting attribute, res=%ld\n", res);
        return res;
    }

    dump_bytes(name, attrs[0].pValue, attrs[0].ulValueLen);
    free(attrs[0].pValue);

    return CKR_OK;
}

int main(int argc, char** argv) {
    CK_RV res = C_Initialize(NULL_PTR);
    if (res != CKR_OK) {
        printf("Fail C_Initialize, res=%ld\n", res);
        return 1;
    }

    CK_SESSION_HANDLE session;
    res = C_OpenSession((CK_SLOT_ID)0, (CK_FLAGS)0, NULL_PTR, NULL_PTR, &session);
    if (res != CKR_OK) {
        printf("Fail C_OpenSession, res=%ld", res);
        return 1;
    }

    res = get_and_dump_attribute(session, CKA_EC_PARAMS, "group");
    if (res != CKR_OK) {
        printf("Fail get_and_dump_attribute for attribute CKa_EC_PARAMS\n");
        return 1;
    }

    res = get_and_dump_attribute(session, CKA_EC_POINT, "point");
    if (res != CKR_OK) {
        printf("Fail get_and_dump_attribute for attribute CKa_EC_PARAMS\n");
        return 1;
    }

    // CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
    const unsigned char DATA[] = {
      0xb5, 0xbb, 0x9d, 0x80, 0x14, 0xa0, 0xf9, 0xb1, 0xd6, 0x1e, 0x21, 0xe7,
      0x96, 0xd7, 0x8d, 0xcc, 0xdf, 0x13, 0x52, 0xf2, 0x3c, 0xd3, 0x28, 0x12,
      0xf4, 0x85, 0x0b, 0x87, 0x8a, 0xe4, 0x94, 0x4c
    };

    unsigned char *dgst = (unsigned char*)DATA;
    CK_ULONG siglen = 0;
    res = C_Sign(session, dgst, sizeof(DATA), NULL_PTR, &siglen);
    if (res != CKR_OK) {
        printf("Failed to call C_Sign to get signature size, res=%ld\n", res);
        return 1;
    }

    unsigned char* sig = malloc(siglen);
    res = C_Sign(session, dgst, sizeof(DATA), sig, &siglen);
    if (res != CKR_OK) {
        printf("Fail C_Sign, res=%ld\n", res);
        return 1;
    }
    dump_bytes("sig", sig, siglen);
    free(sig);

    res = C_CloseSession(session);
    if (res != CKR_OK) {
        printf("Failed to call C_CloseSession, res=%ld", res);
        return 1;
    }

    res = C_Finalize(NULL_PTR);
    if (res != CKR_OK) {
        printf("Fail C_Finalize, res=%ld\n", res);
        return 1;
    }

    printf("Test successful!\n");
    return 0;
}
