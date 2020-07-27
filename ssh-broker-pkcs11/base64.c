#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

char* base64_encode(const unsigned char *input, int length) {
  const int pl = 4*((length+2)/3);
  unsigned char* output = malloc(pl+1); //+1 for the terminating null that EVP_EncodeBlock adds on
  if (output == NULL) {
    return NULL;
  }
  const int ol = EVP_EncodeBlock(output, input, length);
  if (ol != pl) {
    free(output);
    return NULL;
  }
  return (char*)output;
}

unsigned char* base64_decode(const char *input, unsigned long* pulOutLength) {
  const size_t length = strlen(input);
  const int pl = 3*length/4;
  unsigned char *output = malloc(pl);
  if (output == NULL) {
    return NULL;
  }

  EVP_ENCODE_CTX* ctx = EVP_ENCODE_CTX_new();

  int ol;
  if (EVP_DecodeUpdate(ctx, output, &ol, (const unsigned char*)input, length) < 0) {
    free(output);
    EVP_ENCODE_CTX_free(ctx);
    return NULL;
  }
  int fl;
  if (EVP_DecodeFinal(ctx, output+ol, &fl) < 0) {
    free(output);
    EVP_ENCODE_CTX_free(ctx);
    return NULL;
  }

  EVP_ENCODE_CTX_free(ctx);
  *pulOutLength = ol + fl;
  return output;
}
