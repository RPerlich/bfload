/*

*/

#include <stdio.h>
#include <stdlib.h>

const char base64Chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t base64_encoded_size(size_t inLen)
{
    size_t ret;

	ret = inLen;
	
    if (inLen % 3 != 0)
		ret += 3 - (inLen % 3);
	ret /= 3;
	ret *= 4;

	return ret;
}

char *rp_base64_encode(const unsigned char *in, size_t len)
{
	char   *out;
	size_t  elen;
	size_t  i;
	size_t  j;
	size_t  v;

	if (in == NULL || len == 0)
		return NULL;

	elen = base64_encoded_size(len);
	out  = malloc(elen + 1);
	out[elen] = '\0';

	for (i = 0, j = 0; i < len; i += 3, j += 4) {
		v = in[i];
		v = i+1 < len ? v << 8 | in[i + 1] : v << 8;
		v = i+2 < len ? v << 8 | in[i + 2] : v << 8;

		out[j]   = base64Chars[(v >> 18) & 0x3F];
		out[j + 1] = base64Chars[(v >> 12) & 0x3F];
		if (i + 1 < len) {
			out[j + 2] = base64Chars[(v >> 6) & 0x3F];
		} else {
			out[j + 2] = '=';
		}
		if (i + 2 < len) {
			out[j + 3] = base64Chars[v & 0x3F];
		} else {
			out[j + 3] = '=';
		}
	}

	return out;
}
