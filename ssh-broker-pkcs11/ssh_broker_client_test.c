#include <stdio.h>
#include "ssh_broker_client.h"

void dump_bytes(const unsigned char* data, size_t datalen) {
  for (size_t i = 0; i < datalen; i++) {
    printf("%.2X", data[i]);
  }
}

int main(int argc, char** argv) {
    ListKeysResponse* res = list_keys();

    if (res == NULL) {
        printf("Error calling list_keys()\n");
        return 1;
    }
    printf("Found keys: %lu\n", res->keys_length);

    const unsigned char DATA[] = {
      0xb5, 0xbb, 0x9d, 0x80, 0x14, 0xa0, 0xf9, 0xb1, 0xd6, 0x1e, 0x21, 0xe7,
      0x96, 0xd7, 0x8d, 0xcc, 0xdf, 0x13, 0x52, 0xf2, 0x3c, 0xd3, 0x28, 0x12,
      0xf4, 0x85, 0x0b, 0x87, 0x8a, 0xe4, 0x94, 0x4c
    };
    unsigned char *dgst = (unsigned char*)DATA;

    for (size_t i = 0; i < res->keys_length; i++) {
      RemoteKey* key = res->keys[i];
      printf("  keys[%lu].keyName=%s\n", i, key->key_name);
      printf("  keys[%lu].publicKey=", i);
      dump_bytes(key->public_key, key->public_key_length);
      printf("\n");

      size_t sigLen;
      unsigned char* sig;
      ssh_broker_sign(key->public_key, key->public_key_length,
        dgst, sizeof(DATA), &sig, &sigLen);
      printf("  keys[%lu].sig=", i);
      if (sig == NULL) {
        printf("NULL");
      } else {
        dump_bytes(sig, sigLen);
      }
      printf("\n");

      printf("\n");
    }

    ListKeysResponse_free(res);
    return 0;
}
