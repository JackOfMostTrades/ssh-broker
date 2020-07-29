
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

typedef struct _SshBrokerClient {
    char* hostname;
    char* capath;
    char* client_cert_path;
    char* client_key_path;
} SshBrokerClient;

SshBrokerClient* SshBrokerClient_new();
void SshBrokerClient_free(SshBrokerClient*);

typedef enum _SignatureAlgorithm {
    NONE_WITH_ECDSA = 1,
    SHA256_WITH_ECDSA = 2,
    NONE_WITH_RSA = 3,
    SHA1_WITH_RSA = 4,
    SHA256_WITH_RSA = 5,
    SHA512_WITH_RSA = 6,
} SignatureAlgorithm;

ListKeysResponse* ssh_broker_list_keys(SshBrokerClient* client);
void ssh_broker_sign(SshBrokerClient* client, SignatureAlgorithm signature_algorithm,
                     const unsigned char* public_key, size_t public_key_length,
                     const unsigned char* dgst, size_t dgst_length,
                     unsigned char** pOutSignature, size_t* pOutSignatureLength);