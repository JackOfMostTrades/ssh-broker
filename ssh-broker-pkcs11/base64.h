/* Base64 encodes a binary input with the given length. The output will be NULL-terminated. The caller must be free()
   the output. Will return NULL on error.
*/
char* base64_encode(const unsigned char *input, int length);

/* Base64 decodes a NULL-terminated string. The length of the output will be written to the pulOutLength pointer. The
   caller must free() the output. Will return NULL on error.
*/
unsigned char* base64_decode(const char *input, unsigned long* pulOutLength);
