
typedef struct _RemoteKey {
     char* key_name;
     unsigned char* public_key;
     size_t public_key_length;
} RemoteKey;

RemoteKey* RemoteKey_new();
void RemoteKey_free(RemoteKey*);

typedef struct _ListKeysResponse {
    RemoteKey** keys;
    unsigned long keys_length;
} ListKeysResponse;

ListKeysResponse* ListKeysResponse_new();
void ListKeysResponse_free(ListKeysResponse*);

typedef struct _SignRequest {
    unsigned char* public_key;
    char* signature_algorithm;
    unsigned char* data;
} SignRequest;

SignRequest* SignRequest_new();
void SignRequest_free(SignRequest*);

ListKeysResponse* list_keys();
void ssh_broker_sign(const unsigned char* public_key, size_t public_key_length,
                     const unsigned char* dgst, size_t dgst_length,
                     unsigned char** pOutSignature, size_t* pOutSignatureLength);