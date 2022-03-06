/*

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rp_str_list.h"

#ifdef __cplusplus
extern "C" {
#endif

strNode *createStrNode(void)
{
	strNode *node = malloc(sizeof(strNode));
	
	if (node != NULL) {
		node->_str = NULL;
		node->_next = NULL;
	}

	return node;
}

void freeStrNode(strNode *node)
{
	if (node != NULL)
		free(node);
}

strList *rpStrListCreate(void)
{
	strList *list = malloc(sizeof(strList));
	
	if (list != NULL) {
		strNode *node = createStrNode();
		list->_first = node;
	}

	return list;
}

void rpStrListFree(strList *list)
{
	if (list == NULL)
		return;

	strNode *node = list->_first;
	strNode *next;
	
	while (node != NULL) {
		next = node->_next;
		free(node);
		node = next;
	}

	free(list);
	list = NULL;
}

int rpStrListGetCount(strList *list)
{
	if (list == NULL)
		return -1;

	strNode *node = list->_first;
	int length = 0;

	while (node->_next != NULL) {
		length++;
		node = node->_next;
	}

	return length;
}

int rpStrListAppend(strList *list, const char *str)
{
	if (list == NULL || str == NULL)
		return -1;

	strNode *node = list->_first;
	
	while (node->_next != NULL) {
		node = node->_next;
	}

	node->_str = str;
	node->_next = createStrNode();

	return 0;
}

const char *rpStrListGet(strList *list, int index) 
{
	if (list == NULL || index < 0 || index > rpStrListGetCount(list) - 1)
		return NULL;

	strNode *node = list->_first;
	
	while (index > 0) {
		node = node->_next;
		index--;
	}
	
	return node->_str;
}

int rpStrListRemove(strList *list, int index)
{
	if (list == NULL || index < 0 || index > rpStrListGetCount(list) - 1)
		return -1;

	if (index == 0) {
		strNode *node = list->_first;
		list->_first = list->_first->_next;
		freeStrNode(node);
	}
	else {
		strNode *before = list->_first;
		
		while (index > 1) {
			before = before->_next;
			index--;
		}
		
		strNode *node = before->_next;
		before->_next = before->_next->_next;
		freeStrNode(node);
	}

	return 0;
}

//-------------------------------------------------------------------

bfNode *createBFNode(void)
{
	bfNode *node = malloc(sizeof(bfNode));
	
	if (node != NULL) {
		node->_name = NULL;
		node->_hash = NULL;
		node->_seqNo = -1;
		node->_next = NULL;
	}

	return node;
}

void freeBFNode(bfNode *node)
{
	if (node != NULL)
		free(node);
}

bfList *rpBFListCreate(void) 
{
	bfList *list = malloc(sizeof(bfList));
	
	if (list != NULL) {
		bfNode *node = createBFNode();
		list->_first = node;
	}

	return list;
}

void rpBFListFree(bfList *list)
{
	if (list == NULL)
		return;

	bfNode *node = list->_first;
	bfNode *next;
	
	while (node != NULL) {
		next = node->_next;
		free(node);
		node = next;
	}

	free(list);
	list = NULL;
}

int rpBFListGetCount(bfList *list)
{
	if (list == NULL)
		return -1;

	bfNode *node = list->_first;
	int length = 0;

	while (node->_next != NULL) {
		length++;
		node = node->_next;
	}

	return length;
}

int rpBFListAppend(bfList *list, const char *name, const char *hash, unsigned int seqNo)
{
	if (list == NULL || name == NULL)
		return -1;

	bfNode *node = list->_first;
	
	while (node->_next != NULL) {
		node = node->_next;
	}

	node->_name = name;
	node->_hash = hash;
	node->_seqNo = seqNo;
	node->_next = createBFNode();

	return 0;
}

bfNode *rpBFListGet(bfList *list, int index) 
{
	if (list == NULL || index < 0 || index > rpBFListGetCount(list) - 1)
		return NULL;

	bfNode *node = list->_first;
	
	while (index > 0) {
		node = node->_next;
		index--;
	}
	
	return node;
}

int rpBFListRemove(bfList *list, int index)
{
	if (list == NULL || index < 0 || index > rpBFListGetCount(list) - 1)
		return -1;

	if (index == 0) {
		bfNode *node = list->_first;
		list->_first = list->_first->_next;
		freeBFNode(node);
	}
	else {
		bfNode *before = list->_first;
		
		while (index > 1) {
			before = before->_next;
			index--;
		}
		
		bfNode *node = before->_next;
		before->_next = before->_next->_next;
		freeBFNode(node);
	}

	return 0;
}

#ifdef __cplusplus
}
#endif
