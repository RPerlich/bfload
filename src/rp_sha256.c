/*

*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>

#ifdef __cplusplus
extern "C" {
#endif

void rp_sha256_string(char *inString, char out[SHA256_DIGEST_LENGTH * 2 + 1])
{
	unsigned char hash[SHA256_DIGEST_LENGTH];

	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, inString, strlen(inString));
	SHA256_Final(hash, &sha256);

	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		sprintf(out + (i * 2), "%02x", hash[i]);
	}
    
	out[SHA256_DIGEST_LENGTH * 2] = 0;
}

void rp_sha256_file(char *inPath, char out[SHA256_DIGEST_LENGTH * 2 + 1])
{
	FILE *file = fopen(inPath, "rb");
    
	if (!file) return;

	unsigned char hash[SHA256_DIGEST_LENGTH];
	const int bufSize = 32768;
	unsigned char *buffer = malloc(bufSize);
	int bytesRead = 0;

	if (!buffer)
	{
		fclose(file);    
		return;
	}

	SHA256_CTX sha256;
	SHA256_Init(&sha256);

	while ((bytesRead = fread(buffer, 1, bufSize, file)))
	{
		SHA256_Update(&sha256, buffer, bytesRead);
	}
    
	SHA256_Final(hash, &sha256);

	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		sprintf(out + (i * 2), "%02x", hash[i]);
	}

	out[SHA256_DIGEST_LENGTH * 2] = 0;
    
	fclose(file);

	if (buffer)
	{
		free(buffer);
		buffer = NULL;
	}
}

void rp_sha256_file_hash(char *inPath, unsigned char out[SHA256_DIGEST_LENGTH])
{
	FILE *file = fopen(inPath, "rb");
    
	if (!file) return;

	const int bufSize = 32768;
	unsigned char *buffer = malloc(bufSize);
	int bytesRead = 0;

	if (!buffer) 
	{
		fclose(file);
		return;
	}

	SHA256_CTX sha256;
	SHA256_Init(&sha256);

	while ((bytesRead = fread(buffer, 1, bufSize, file)))
	{
		SHA256_Update(&sha256, buffer, bytesRead);
	}
    
	SHA256_Final(out, &sha256);

	fclose(file);
    
	if (buffer)
	{
		free(buffer);
		buffer = NULL;
	}
}

#ifdef __cplusplus
}
#endif