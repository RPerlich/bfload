// run libtoolize
// run autoheader
// create configure.ac
// run aclocal
// run automake --add-missing
// run autoreconf
// run ./configure
// run make
//Include: /usr/include/libxml2

// wsdl2h -o serveBFService.h -c serveBFService.wsdl
// soapcpp2 -c serveBFService.h

/* BFCLOAD - BigFileDownload Tool
 * bfcload.c Copyright (C) 2022 RPSoft
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library. If not, see <http://www.gnu.org/licenses/>.
 */

#include <termios.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>		// isprint
#include <unistd.h>		// getopt
#include <linux/limits.h>
#include <openssl/sha.h>
#include <libxml/parser.h>
#include "soapH.h"
#include "serveBFServiceSoap.nsmap"
#include "curlapi.h"
#include "rp_sha256.h"
#include "rp_base64.h"
#include "rp_tools.h"
#include "rp_str_list.h"

#define client_version "0.6"

typedef struct appConfigStruct {
	char *paramConfigFile;
	char *paramDnlPath;
	char *paramUserName;
	char *paramPassword;
} appConfig;

typedef struct bfConfigStruct {
	unsigned char *bfFileName;
	unsigned char *bfFileHash;
	unsigned char *bfWebAddress;
	unsigned char *bfWebFolder;
	long bfNeededDiskSpace;
	bfList *partList;
} bfConfig;

static volatile int stopPprocessing = 0;

int bf_CheckFileHash(char *fileName, const char *bfFileHash)
{
	unsigned char hash[SHA256_DIGEST_LENGTH];
	int result = -1;

	rp_sha256_file_hash(fileName, hash);
	char *buffer = rp_base64_encode(hash, SHA256_DIGEST_LENGTH);
	result = strcmp(buffer, bfFileHash);

	if (buffer)
	{
		free(buffer);
		buffer = NULL;
	}

	return result;
}

int ws_CheckClientVersion(struct soap *soap) {
  struct _ns1__checkClientVersionResponse ccvr;
  struct _ns1__checkClientVersion ccv;
  ccv.sClientVersion = (char *)client_version;

  int result = soap_call___ns1__checkClientVersion(soap, NULL, NULL, &ccv, &ccvr);
  
  if (result != SOAP_OK)
    result = soap_call___ns1__checkClientVersion(soap, NULL, NULL, &ccv, &ccvr);

  if (result != SOAP_OK)
  {
    fprintf(stdout, "Error: There was a problem accessing the server. Error code: %i\n", result);
    fprintf(stdout, "Please check your credentials and try again.\n");
    return -1;
  }
    
  if (ccvr.checkClientVersionResult == xsd__boolean__false_)
  { 
    fprintf(stdout, "You are using an outdated version (%s).\n", client_version);
    fprintf(stdout, "Please update the program to the latest version and try again.\n");
    return -1;
  }
  
  return result;
}

int ws_GetFilePart(struct soap *soap, char *SvcDnlPath, char *SvcDnlFilePart, char *LocalDnlFile)
{
	struct ns1__stPartInfo fpi;
	struct _ns1__serveFilePart sfp;
	struct _ns1__serveFilePartResponse sfpr;
	FILE *fp;

	fpi.sClientVersion = client_version;
	fpi.sPartFolder = SvcDnlPath;
	fpi.sPartName = SvcDnlFilePart;
	sfp.partInfo = &fpi;

	int result = soap_call___ns1__serveFilePart(soap, NULL, NULL, &sfp, &sfpr);
  
	if (result == SOAP_OK)
	{
		fp = fopen(LocalDnlFile, "wb");

		if (fp == NULL)
		{
			//fprintf(stdout, "Error: Failed to open file: %s\n", strerror(errno));
			return errno;
		}

		size_t bytesWritten = fwrite(sfpr.serveFilePartResult.__ptr, 1, sfpr.serveFilePartResult.__size, fp);
		fflush(fp);
		fclose(fp);

		if ((int)bytesWritten != sfpr.serveFilePartResult.__size)
    {
			//fprintf(stdout, "Error: Failed to write file: %s\n", strerror(errno));
			return errno;
    }
  }

  return result;
}

int ws_DownloadFileParts(struct soap *soap, bfConfig *bfc, appConfig *appCfg)
{
	char *dnlFile = NULL;
	int len = rpBFListGetCount(bfc->partList);
	int cnt = 0;
	int dnlResult = 0;

	for (int i = 0; i < len; i++)
	{
		dnlResult = stopPprocessing;
		
		if (dnlResult == 1)
			break;

		bfNode *part = rpBFListGet(bfc->partList, i);
		dnlFile = rp_PathCombine(appCfg->paramDnlPath, part->_name);
		
		if (dnlFile == NULL)
		{
			fprintf(stdout, "Error: There was a problem building the download path for file part '%s'\n", part->_name);
			return -1;
		}

		if (rp_FileExists(dnlFile) == -1)
		{
			fprintf(stdout, "Downloading file part '%s' [%i of %i]...", part->_name, i + 1, len);

			int dnlResult = ws_GetFilePart(soap, (char *)bfc->bfWebFolder, (char *)part->_name, dnlFile);
			
			if (dnlResult == 0)
				fprintf(stdout, " Done.\n");
			else
				fprintf(stdout, " Failed with error %i.\n", dnlResult);
		}
		else
		{
			fprintf(stdout, "Skip download of file part '%s', file already exists.\n", part->_name);
		}

		if (dnlResult == 0)
		{
			fprintf(stdout, "Verifying the checksum of file part '%s'...", dnlFile);

			if (bf_CheckFileHash(dnlFile, part->_hash) == 0)
			{
				fprintf(stdout, " Success.\n");			
				cnt++;
			}
			else
				fprintf(stdout, " Failed.");			
		}

		if (dnlFile)
		{
			free(dnlFile);
			dnlFile = NULL;
		}
	}

	return (len == cnt) ? 0 : -1;
}

bfNode* bf_GetPartNodeForSeqNo(bfList *partList, unsigned int seqNo)
{
	int len = rpBFListGetCount(partList);
	bfNode *node = NULL;

	for (int i = 0; i < len; i++)
	{
		node = rpBFListGet(partList, i);

		if (node->_seqNo == seqNo + 1)
			return node;
	}

	return NULL;
}

int bf_ConcatFileParts(bfConfig *bfc, appConfig *appCfg)
{
	char *srcFileName = NULL;
	char *dstFileName = NULL;
	char *delFileName = NULL;
	FILE *srcFile = NULL;
	FILE *dstFile = NULL;
	int len = rpBFListGetCount(bfc->partList);
	int bytesRead = 0;
	int bytesWritten = 0;
	int catResult = 0;
	const int bufSize = 65536;
	unsigned char *buffer = malloc(bufSize);

	fprintf(stdout, "Start concatenating the file parts...\n");

	if (!buffer)
	{
		fprintf(stdout, "Error: Failed to allocate enought memory to concate the file parts.\n");
		return -1;
	}

	dstFileName = rp_PathCombine(appCfg->paramDnlPath, (const char *)bfc->bfFileName);

	if (dstFileName == NULL)
	{
		fprintf(stdout, "Error: There was a problem building the destination path for file '%s'\n", bfc->bfFileName);
		return -1;
	}

	dstFile = fopen(dstFileName, "wb");

	if (!dstFile)
	{
		fprintf(stdout, "Error: There was a problem creating the destination file '%s'\n", dstFileName);
		return -1;
	}

	for (int i = 0; i < len; i++)
	{
		bytesRead = 0;
		bytesWritten = 0;

		if (stopPprocessing == 1)
		{
			catResult = -1;
			break;
		}

		bfNode *part = bf_GetPartNodeForSeqNo(bfc->partList, (unsigned int)i);
		
		if (part == NULL)
		{
			fprintf(stdout, "Error: There was a problem getting the sequence number for file part '%i'\n", i + 1);
			catResult = -1;
			break;
		}

		srcFileName = rp_PathCombine(appCfg->paramDnlPath, part->_name);
		
		if (srcFileName == NULL)
		{
			fprintf(stdout, "Error: There was a problem building the source path for file part '%s'\n", part->_name);
			catResult = -1;
			break;
		}

		srcFile = fopen(srcFileName, "rb");

		if (srcFile)
		{
			fprintf(stdout, "Concatenating file part '%s' [%i of %i]...", part->_name, i + 1, len);

			while ((bytesRead = fread(buffer, 1, bufSize, srcFile)))
			{
				bytesWritten = fwrite(buffer, 1, bytesRead, dstFile);

				if (bytesRead != bytesWritten)
				{
					catResult = -1;
					break;
				}
			}

			fclose(srcFile);
			srcFile = NULL;

			if (catResult == -1)
				fprintf(stdout, " FAILED.\n");
			else
				fprintf(stdout, " Done.\n");
		}
		else
		{
			fprintf(stdout, "Error: There was a problem opening the socurce file '%s'\n", srcFileName);
			catResult = -1;
			break;
		}

		if (srcFileName)
		{
			free(srcFileName);
			srcFileName = NULL;
		}
	
		if (catResult == -1)
			break;
	}
		
	if (buffer)
	{
		free(buffer);
		buffer = NULL;
	}

	fflush(dstFile);
	fclose(dstFile);
	dstFile = NULL;
	
	if (catResult == 0)
	{
		fprintf(stdout, "Verifying the checksum of final file '%s'...", dstFileName);

		if (bf_CheckFileHash(dstFileName, (const char *)bfc->bfFileHash) == 0)
			fprintf(stdout, " Success.\n");
		else
		{
			fprintf(stdout, " Failed.");
			catResult = -1;
		}
	}

	if (catResult == 0)
	{
		fprintf(stdout, "Cleaning up the temporary file parts...\n");

		for (int d = 0; d < len; d++)
		{
			bfNode *delpart = rpBFListGet(bfc->partList, (unsigned int)d);

			if (delpart == NULL)
			{
				fprintf(stdout, "Error: There was a problem cleaing up  file part '%i'\n", d + 1);
				catResult = -1;
				break;
			}

			delFileName = rp_PathCombine(appCfg->paramDnlPath, delpart->_name);
		
			if (delFileName == NULL)
			{
				fprintf(stdout, "Error: There was a problem building the cleanup path for file part '%s'\n", delpart->_name);
				catResult = -1;
				break;
			}

			catResult = remove(delFileName);

			if (delFileName)
			{
				free(delFileName);
				delFileName = NULL;
			}
		}
	}

	if (dstFileName)
	{
		free(dstFileName);
		dstFileName = NULL;
	}

	return catResult;
}

int bf_LoadConfig(bfConfig *bfc, char *bfcConfigFile)
{
  xmlDoc *document;
  xmlNode *root, *first_child, *node;

  document = xmlReadFile(bfcConfigFile, NULL, 0);
  
	if (document == NULL)
	{
		fprintf(stdout, "Error: There was a problem reading the configuration file. Error code: %i\n", errno);
    fprintf(stdout, "Please check the path to the configuration file and try again.\n");
		return -1;
	}

	root = xmlDocGetRootElement(document);

	if (root == NULL)
	{
		fprintf(stdout, "Error: There was a problem reading the configuration file. Error code: %i\n", errno);
    fprintf(stdout, "Please check the content of the configuration file and try again.\n");
		return -1;
	}

  first_child = root->children;

  for (node = first_child; node; node = node->next)
  {
    if (node->type == XML_TEXT_NODE)
      continue;

    if (strcmp((const char *)node->name, "BFFileName") == 0)
    {
      bfc->bfFileName = xmlNodeListGetString(document, node->xmlChildrenNode, 1);
      bfc->bfFileHash = xmlGetProp(node, (const unsigned char *)"Hash");
      continue;
    }

    if (strcmp((const char *)node->name, "BFWebAddress") == 0)
    {
      bfc->bfWebAddress = xmlNodeListGetString(document, node->xmlChildrenNode, 1);
      continue;
    }

    if (strcmp((const char *)node->name, "BFWebFolder") == 0)
    {
      bfc->bfWebFolder = xmlNodeListGetString(document, node->xmlChildrenNode, 1);
      continue;
    }

    if (strcmp((const char *)node->name, "BFNeededDiskSpace") == 0)
    {
      long ret = strtol((const char *)xmlNodeListGetString(document, node->xmlChildrenNode, 1), NULL, 10);
      bfc->bfNeededDiskSpace = ret;
      continue;
    }

    if (strcmp((const char *)node->name, "BFParts") == 0)
    {
      xmlChar *name = xmlNodeListGetString(document, node->xmlChildrenNode, 1);
      xmlChar *hash = xmlGetProp(node, (const unsigned char *)"Hash");
      unsigned int seqNo = atoi((const char *)xmlGetProp(node, (const unsigned char *)"SeqNo"));
      rpBFListAppend(bfc->partList, (const char *)name, (const char *)hash, seqNo);
    }
  }

  xmlFreeDoc(document);

	if (bfc->bfFileName == NULL || bfc->bfFileHash == NULL || bfc->bfWebAddress == NULL ||
			bfc->bfWebFolder == NULL || bfc->bfNeededDiskSpace <= 0 || rpBFListGetCount(bfc->partList) == 0)
	{
		fprintf(stdout, "Error: There was a problem reading the configuration file. Error code: %i\n", errno);
    fprintf(stdout, "Please check the content of the configuration file and try again.\n");
		return -1;
	}

  return 0;
}

void bf_GetPassword(char *password)
{
	static struct termios old_terminal;
	static struct termios new_terminal;

	//get terminal settings and disable echo
	tcgetattr(STDIN_FILENO, &old_terminal);
	new_terminal = old_terminal;
	new_terminal.c_lflag &= ~(ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &new_terminal);

	if (fgets(password, BUFSIZ, stdin) == NULL)
		password[0] = '\0';
	else
		password[strlen(password)-1] = '\0';

	// restore terminal settings
	tcsetattr(STDIN_FILENO, TCSANOW, &old_terminal);
}

int bf_SOAPSetup(struct soap **soap, CURL **curl, appConfig *appCfg)
{
  curl_global_init(CURL_GLOBAL_ALL);
  *curl = curl_easy_init();

  curl_easy_setopt(*curl, CURLOPT_USERNAME, appCfg->paramUserName);
  curl_easy_setopt(*curl, CURLOPT_PASSWORD, appCfg->paramPassword);
  curl_easy_setopt(*curl, CURLOPT_HTTPAUTH, CURLAUTH_NTLM);
  curl_easy_setopt(*curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");
  curl_easy_setopt(*curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
  //curl_easy_setopt(*curl, CURLOPT_VERBOSE, 1L);

  *soap = soap_new1(SOAP_XML_INDENT);
  soap_register_plugin_arg(*soap, soap_curl, *curl);

	return 0;
}

void bf_SoapCleanup(struct soap **soap, CURL **curl)
{
  soap_destroy(*soap);
  soap_end(*soap);
  soap_free(*soap);
  curl_easy_cleanup(*curl);
  curl_global_cleanup();

  *soap = NULL;
  *curl = NULL;
}

int bf_Run(appConfig *appCfg)
{
	int result = -1;
	bfConfig *bfc = NULL;
	struct soap *soap = NULL;
  CURL *curl = NULL;

	bfc = malloc(sizeof(bfConfig));
	bfc->bfFileName = NULL;
  bfc->bfFileHash = NULL;
	bfc->bfWebAddress = NULL;
	bfc->bfWebFolder = NULL;
	bfc->bfNeededDiskSpace = 0;
	bfc->partList = rpBFListCreate();

	result = bf_LoadConfig(bfc, appCfg->paramConfigFile);

	if (result == 0)
	{
		result = rp_PathExists(appCfg->paramDnlPath);
		
		if (result != 0)
		{
			fprintf(stdout, "Error: Path: '%s' not exists.\n", appCfg->paramDnlPath);
			fprintf(stdout, "Please check the download path and try again.\n");
		}
	}

	if (result == 0)
	{
		long freeSpace = rp_GetFreeSpace(appCfg->paramDnlPath);  // -1, errorno

		if ((freeSpace == -1) || (bfc->bfNeededDiskSpace * 2 > freeSpace))
		{
			fprintf(stdout, "Error: Not enought space to download the file (%ld bytes needed).\n", bfc->bfNeededDiskSpace * 2);
			fprintf(stdout, "Please make sure you have enought space avaialbe and try again.\n");
		}
		else
			result = 0;
	}

	if (result == 0)
	{
		bf_SOAPSetup(&soap, &curl, appCfg); // check return

		fprintf(stdout, "Checking program client version...\n");
	
		result = ws_CheckClientVersion(soap);
	}

	if (result == 0)
		result = ws_DownloadFileParts(soap, bfc, appCfg);
	
	if (result != 0)
		fprintf(stdout, "Error: Failed to download all required file parts.\n");

	if (result == 0)
		result = bf_ConcatFileParts(bfc, appCfg);
	
	bf_SoapCleanup(&soap, &curl);
	rpBFListFree(bfc->partList);
	
	if (bfc) 
	{
		free(bfc);
		bfc = NULL;
	}

	return result;
}

void showUsage(void)
{
  fprintf(stdout, "Usage: bfload [OPTION]...\n"
    "Download a big file from a web service.\n\n"
  	" -c  <file>  Configuration file (.bfc)\n"
		" -d  <path>  Path where you want to save the file\n"
		" -h          Show this help message\n"
		" -u  <user>  User name (e.g DOMAIN\\USER)\n\n");
}

void intHandler(__attribute__((unused))int signal) {
    stopPprocessing = 1;
}

int main(int argc, char **argv) 
{
	signal(SIGINT, intHandler);

	fprintf(stdout, "BigFile Service Client. Version %s\n\n", client_version);

	appConfig appCfg;
	appCfg.paramConfigFile = NULL;
	appCfg.paramDnlPath = NULL;
	appCfg.paramUserName = NULL;
	appCfg.paramPassword = NULL;
  
	int c = 0;
	opterr = 0;

	while ((c = getopt(argc, argv, "c:d:u:h")) != -1)
		switch (c)
		{
			case 'c':
				appCfg.paramConfigFile = optarg;
				break;
			case 'd':
				appCfg.paramDnlPath = optarg;
				break;
			case 'u':
				appCfg.paramUserName = optarg;
				break;
			case 'h':
			{
				showUsage();
				exit(1);
			}
			case '?':
				if (optopt == 'c' || optopt == 'p' || optopt == 'u')
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				else if (isprint (optopt))
					fprintf (stderr, "Unknown option `-%c'.\n", optopt);
				else
					fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
  				exit(1);
			default:
      {
				showUsage();
				exit(1);
  		}
		}

  if ((appCfg.paramConfigFile == NULL) || (appCfg.paramDnlPath == NULL) || (appCfg.paramUserName == NULL))
  {
    showUsage();
    exit(1);
  }

	fprintf(stdout, "Please provide the password for user '%s': ", appCfg.paramUserName);
	char *pwBuf = malloc(BUFSIZ);
	bf_GetPassword(pwBuf);
	appCfg.paramPassword = pwBuf;
	
	fprintf(stdout, "\nStart downloading...\n");
	bf_Run(&appCfg);

	if (appCfg.paramPassword)
		free(appCfg.paramPassword);

	fprintf(stdout, "Done.\n");

  return 0;
}
