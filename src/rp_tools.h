/*

*/

#ifdef __cplusplus
extern "C" {
#endif

long rp_GetFreeSpace(const char* path);
short rp_PathExists(const char* path);
short rp_FileExists(const char *file);
char* rp_PathCombine(const char *path, const char *file);

#ifdef __cplusplus
}
#endif