/*

*/

#ifdef __cplusplus
extern "C" {
#endif

typedef struct strNodeStruct {
	const char *_str;
	struct strNodeStruct *_next;
} strNode;

typedef struct strListStruct {
	struct strNodeStruct *_first;
} strList;

strList *rpStrListCreate(void);
void rpStrListFree(strList *list);
int	rpStrListGetCount(strList *list);
int rpStrListAppend(strList *list, const char *str);
const char *rpStrListGet(strList *list, int index);
int rpStrListRemove(strList *list, int index);

//-------------------------------------------------------------------

typedef struct bfNodeStruct {
	const char *_name;
	const char *_hash;
	unsigned int _seqNo;
	struct bfNodeStruct *_next;
} bfNode;

typedef struct bfListStruct {
	struct bfNodeStruct *_first;
} bfList;

bfList *rpBFListCreate(void);
void rpBFListFree(bfList *list);
int	rpBFListGetCount(bfList *list);
int rpBFListAppend(bfList *list, const char *name, const char *hash, unsigned int seqNo);
bfNode *rpBFListGet(bfList *list, int index);
int rpBFListRemove(bfList *list, int index);

#ifdef __cplusplus
}
#endif
