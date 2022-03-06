/*

*/

#include <openssl/sha.h>

#ifdef __cplusplus
extern "C" {
#endif

void rp_sha256_string(char *inString, char out[SHA256_DIGEST_LENGTH * 2 + 1]);
void rp_sha256_file(char *inPath, char out[SHA256_DIGEST_LENGTH * 2 + 1]);
void rp_sha256_file_hash(char *inPath, unsigned char out[SHA256_DIGEST_LENGTH]);

#ifdef __cplusplus
}
#endif