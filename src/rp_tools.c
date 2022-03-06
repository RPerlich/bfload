/*

*/
#define _GNU_SOURCE 

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/statvfs.h>

long rp_GetFreeSpace(const char* path)
{
  struct statvfs stat;

  if (statvfs(path, &stat) != 0)
    return -1;

  return stat.f_bsize * stat.f_bavail;
}

short rp_PathExists(const char* path)
{
	struct stat stats;

	if (stat(path, &stats) == 0)
		if (S_ISDIR(stats.st_mode))
			return 0;

	return -1;
}

short rp_FileExists(const char *file)
{
  struct stat stats;   
  if (stat (file, &stats) == 0)
		return 0;

	return -1;
}

const char *last_char_is(const char *s, const int c)
{
	const char *sret = s + strlen(s) - 1;
	
	if (sret >= s && *sret == c)
		return sret;
	else 
		return NULL;
}

char* rp_PathCombine(const char *path, const char *file)
{
	const char *lc;
	char *retPath = NULL;
	
	if (!path)
		path = "";
	
	lc = last_char_is(path, '/');
	
	while (*file == '/')
		file++;
	
	if (asprintf(&retPath, "%s%s%s", path, (lc == NULL ? "/" : ""), file) != -1)
		return retPath;
	else
		return NULL;
}