/* soapStub.h
   Generated by gSOAP 2.8.119 for bfsrv.h

gSOAP XML Web services tools
Copyright (C) 2000-2021, Robert van Engelen, Genivia Inc. All Rights Reserved.
The soapcpp2 tool and its generated software are released under the GPL.
This program is released under the GPL with the additional exemption that
compiling, linking, and/or using OpenSSL is allowed.
--------------------------------------------------------------------------------
A commercial use license is available from Genivia Inc., contact@genivia.com
--------------------------------------------------------------------------------
*/

#define SOAP_NAMESPACE_OF_ns1	"http://onsite.it-solutions.atos.net/webservices"

#ifndef soapStub_H
#define soapStub_H
#include "stdsoap2.h"
#if GSOAP_VERSION != 208119
# error "GSOAP VERSION 208119 MISMATCH IN GENERATED CODE VERSUS LIBRARY CODE: PLEASE REINSTALL PACKAGE"
#endif


/******************************************************************************\
 *                                                                            *
 * Enumeration Types                                                          *
 *                                                                            *
\******************************************************************************/


/* bfsrv.h:150 */
#ifndef SOAP_TYPE_xsd__boolean
#define SOAP_TYPE_xsd__boolean (11)
/* xsd:boolean */
enum xsd__boolean {
	xsd__boolean__false_ = 0,
	xsd__boolean__true_ = 1
};
#endif

/******************************************************************************\
 *                                                                            *
 * Types with Custom Serializers                                              *
 *                                                                            *
\******************************************************************************/


/******************************************************************************\
 *                                                                            *
 * Structs and Unions                                                         *
 *                                                                            *
\******************************************************************************/

struct xsd__base64Binary;	/* bfsrv.h:143 */
struct ns1__stPartInfo;	/* bfsrv.h:179 */
struct _ns1__checkClientVersion;	/* bfsrv.h:199 */
struct _ns1__checkClientVersionResponse;	/* bfsrv.h:215 */
struct _ns1__serveFilePart;	/* bfsrv.h:231 */
struct _ns1__serveFilePartResponse;	/* bfsrv.h:247 */
struct __ns1__checkClientVersion;	/* bfsrv.h:389 */
struct __ns1__serveFilePart;	/* bfsrv.h:448 */
struct __ns1__checkClientVersion_;	/* bfsrv.h:507 */
struct __ns1__serveFilePart_;	/* bfsrv.h:566 */

/* bfsrv.h:143 */
#ifndef SOAP_TYPE_xsd__base64Binary
#define SOAP_TYPE_xsd__base64Binary (7)
/* binary data attached as MTOM/MIME/DIME attachment or included as *`xsd:base64Binary`* base64: */
struct xsd__base64Binary {
        unsigned char *__ptr;
        int __size;
        /** Optional element 'id' of XML schema type 'xsd:string' */
        char *id;
        /** Optional element 'type' of XML schema type 'xsd:string' */
        char *type;
        /** Optional element 'options' of XML schema type 'xsd:string' */
        char *options;
};
#endif

/* bfsrv.h:179 */
#ifndef SOAP_TYPE_ns1__stPartInfo
#define SOAP_TYPE_ns1__stPartInfo (12)
/* complex XML schema type 'ns1:stPartInfo': */
struct ns1__stPartInfo {
        /** Optional element 'ns1:sPartName' of XML schema type 'xsd:string' */
        char *sPartName;
        /** Optional element 'ns1:sPartFolder' of XML schema type 'xsd:string' */
        char *sPartFolder;
        /** Optional element 'ns1:sClientVersion' of XML schema type 'xsd:string' */
        char *sClientVersion;
};
#endif

/* bfsrv.h:199 */
#ifndef SOAP_TYPE__ns1__checkClientVersion
#define SOAP_TYPE__ns1__checkClientVersion (13)
/* complex XML schema type 'ns1:checkClientVersion': */
struct _ns1__checkClientVersion {
        /** Optional element 'ns1:sClientVersion' of XML schema type 'xsd:string' */
        char *sClientVersion;
};
#endif

/* bfsrv.h:215 */
#ifndef SOAP_TYPE__ns1__checkClientVersionResponse
#define SOAP_TYPE__ns1__checkClientVersionResponse (14)
/* complex XML schema type 'ns1:checkClientVersionResponse': */
struct _ns1__checkClientVersionResponse {
        /** Required element 'ns1:checkClientVersionResult' of XML schema type 'xsd:boolean' */
        enum xsd__boolean checkClientVersionResult;
};
#endif

/* bfsrv.h:231 */
#ifndef SOAP_TYPE__ns1__serveFilePart
#define SOAP_TYPE__ns1__serveFilePart (15)
/* complex XML schema type 'ns1:serveFilePart': */
struct _ns1__serveFilePart {
        /** Required element 'ns1:partInfo' of XML schema type 'ns1:stPartInfo' */
        struct ns1__stPartInfo *partInfo;
};
#endif

/* bfsrv.h:247 */
#ifndef SOAP_TYPE__ns1__serveFilePartResponse
#define SOAP_TYPE__ns1__serveFilePartResponse (17)
/* complex XML schema type 'ns1:serveFilePartResponse': */
struct _ns1__serveFilePartResponse {
        /** Optional element 'ns1:serveFilePartResult' of XML schema type 'xsd:base64Binary' */
        struct xsd__base64Binary serveFilePartResult;
};
#endif

/* bfsrv.h:389 */
#ifndef SOAP_TYPE___ns1__checkClientVersion
#define SOAP_TYPE___ns1__checkClientVersion (21)
/* Wrapper: */
struct __ns1__checkClientVersion {
        /** Optional element 'ns1:checkClientVersion' of XML schema type 'ns1:checkClientVersion' */
        struct _ns1__checkClientVersion *ns1__checkClientVersion;
};
#endif

/* bfsrv.h:448 */
#ifndef SOAP_TYPE___ns1__serveFilePart
#define SOAP_TYPE___ns1__serveFilePart (25)
/* Wrapper: */
struct __ns1__serveFilePart {
        /** Optional element 'ns1:serveFilePart' of XML schema type 'ns1:serveFilePart' */
        struct _ns1__serveFilePart *ns1__serveFilePart;
};
#endif

/* bfsrv.h:507 */
#ifndef SOAP_TYPE___ns1__checkClientVersion_
#define SOAP_TYPE___ns1__checkClientVersion_ (27)
/* Wrapper: */
struct __ns1__checkClientVersion_ {
        /** Optional element 'ns1:checkClientVersion' of XML schema type 'ns1:checkClientVersion' */
        struct _ns1__checkClientVersion *ns1__checkClientVersion;
};
#endif

/* bfsrv.h:566 */
#ifndef SOAP_TYPE___ns1__serveFilePart_
#define SOAP_TYPE___ns1__serveFilePart_ (29)
/* Wrapper: */
struct __ns1__serveFilePart_ {
        /** Optional element 'ns1:serveFilePart' of XML schema type 'ns1:serveFilePart' */
        struct _ns1__serveFilePart *ns1__serveFilePart;
};
#endif

/* bfsrv.h:687 */
#ifndef WITH_NOGLOBAL
#ifndef SOAP_TYPE_SOAP_ENV__Header
#define SOAP_TYPE_SOAP_ENV__Header (30)
/* SOAP_ENV__Header: */
struct SOAP_ENV__Header {
#ifdef WITH_NOEMPTYSTRUCT
	char dummy;	/* empty struct is a GNU extension */
#endif
};
#endif
#endif

/* bfsrv.h:687 */
#ifndef WITH_NOGLOBAL
#ifndef SOAP_TYPE_SOAP_ENV__Code
#define SOAP_TYPE_SOAP_ENV__Code (31)
/* Type SOAP_ENV__Code is a recursive data type, (in)directly referencing itself through its (base or derived class) members */
/* SOAP_ENV__Code: */
struct SOAP_ENV__Code {
        /** Optional element 'SOAP-ENV:Value' of XML schema type 'xsd:QName' */
        char *SOAP_ENV__Value;
        /** Optional element 'SOAP-ENV:Subcode' of XML schema type 'SOAP-ENV:Code' */
        struct SOAP_ENV__Code *SOAP_ENV__Subcode;
};
#endif
#endif

/* bfsrv.h:687 */
#ifndef WITH_NOGLOBAL
#ifndef SOAP_TYPE_SOAP_ENV__Detail
#define SOAP_TYPE_SOAP_ENV__Detail (33)
/* SOAP_ENV__Detail: */
struct SOAP_ENV__Detail {
        char *__any;
        /** Any type of element 'fault' assigned to fault with its SOAP_TYPE_<typename> assigned to __type */
        /** Do not create a cyclic data structure through this member unless SOAP encoding or SOAP_XML_GRAPH are used for id-ref serialization */
        int __type;
        void *fault;
};
#endif
#endif

/* bfsrv.h:687 */
#ifndef WITH_NOGLOBAL
#ifndef SOAP_TYPE_SOAP_ENV__Reason
#define SOAP_TYPE_SOAP_ENV__Reason (36)
/* SOAP_ENV__Reason: */
struct SOAP_ENV__Reason {
        /** Optional element 'SOAP-ENV:Text' of XML schema type 'xsd:string' */
        char *SOAP_ENV__Text;
};
#endif
#endif

/* bfsrv.h:687 */
#ifndef WITH_NOGLOBAL
#ifndef SOAP_TYPE_SOAP_ENV__Fault
#define SOAP_TYPE_SOAP_ENV__Fault (37)
/* SOAP_ENV__Fault: */
struct SOAP_ENV__Fault {
        /** Optional element 'faultcode' of XML schema type 'xsd:QName' */
        char *faultcode;
        /** Optional element 'faultstring' of XML schema type 'xsd:string' */
        char *faultstring;
        /** Optional element 'faultactor' of XML schema type 'xsd:string' */
        char *faultactor;
        /** Optional element 'detail' of XML schema type 'SOAP-ENV:Detail' */
        struct SOAP_ENV__Detail *detail;
        /** Optional element 'SOAP-ENV:Code' of XML schema type 'SOAP-ENV:Code' */
        struct SOAP_ENV__Code *SOAP_ENV__Code;
        /** Optional element 'SOAP-ENV:Reason' of XML schema type 'SOAP-ENV:Reason' */
        struct SOAP_ENV__Reason *SOAP_ENV__Reason;
        /** Optional element 'SOAP-ENV:Node' of XML schema type 'xsd:string' */
        char *SOAP_ENV__Node;
        /** Optional element 'SOAP-ENV:Role' of XML schema type 'xsd:string' */
        char *SOAP_ENV__Role;
        /** Optional element 'SOAP-ENV:Detail' of XML schema type 'SOAP-ENV:Detail' */
        struct SOAP_ENV__Detail *SOAP_ENV__Detail;
};
#endif
#endif

/******************************************************************************\
 *                                                                            *
 * Typedefs                                                                   *
 *                                                                            *
\******************************************************************************/


/* (built-in):0 */
#ifndef SOAP_TYPE__XML
#define SOAP_TYPE__XML (5)
typedef char *_XML;
#endif

/* (built-in):0 */
#ifndef SOAP_TYPE__QName
#define SOAP_TYPE__QName (6)
typedef char *_QName;
#endif

/******************************************************************************\
 *                                                                            *
 * Serializable Types                                                         *
 *                                                                            *
\******************************************************************************/


/* char has binding name 'byte' for type 'xsd:byte' */
#ifndef SOAP_TYPE_byte
#define SOAP_TYPE_byte (3)
#endif

/* int has binding name 'int' for type 'xsd:int' */
#ifndef SOAP_TYPE_int
#define SOAP_TYPE_int (1)
#endif

/* unsigned char has binding name 'unsignedByte' for type 'xsd:unsignedByte' */
#ifndef SOAP_TYPE_unsignedByte
#define SOAP_TYPE_unsignedByte (9)
#endif

/* unsigned int has binding name 'unsignedInt' for type 'xsd:unsignedInt' */
#ifndef SOAP_TYPE_unsignedInt
#define SOAP_TYPE_unsignedInt (8)
#endif

/* enum xsd__boolean has binding name 'xsd__boolean' for type 'xsd:boolean' */
#ifndef SOAP_TYPE_xsd__boolean
#define SOAP_TYPE_xsd__boolean (11)
#endif

/* struct SOAP_ENV__Fault has binding name 'SOAP_ENV__Fault' for type '' */
#ifndef SOAP_TYPE_SOAP_ENV__Fault
#define SOAP_TYPE_SOAP_ENV__Fault (37)
#endif

/* struct SOAP_ENV__Reason has binding name 'SOAP_ENV__Reason' for type '' */
#ifndef SOAP_TYPE_SOAP_ENV__Reason
#define SOAP_TYPE_SOAP_ENV__Reason (36)
#endif

/* struct SOAP_ENV__Detail has binding name 'SOAP_ENV__Detail' for type '' */
#ifndef SOAP_TYPE_SOAP_ENV__Detail
#define SOAP_TYPE_SOAP_ENV__Detail (33)
#endif

/* struct SOAP_ENV__Code has binding name 'SOAP_ENV__Code' for type '' */
#ifndef SOAP_TYPE_SOAP_ENV__Code
#define SOAP_TYPE_SOAP_ENV__Code (31)
#endif

/* struct SOAP_ENV__Header has binding name 'SOAP_ENV__Header' for type '' */
#ifndef SOAP_TYPE_SOAP_ENV__Header
#define SOAP_TYPE_SOAP_ENV__Header (30)
#endif

/* struct _ns1__serveFilePartResponse has binding name '_ns1__serveFilePartResponse' for type '' */
#ifndef SOAP_TYPE__ns1__serveFilePartResponse
#define SOAP_TYPE__ns1__serveFilePartResponse (17)
#endif

/* struct _ns1__serveFilePart has binding name '_ns1__serveFilePart' for type '' */
#ifndef SOAP_TYPE__ns1__serveFilePart
#define SOAP_TYPE__ns1__serveFilePart (15)
#endif

/* struct _ns1__checkClientVersionResponse has binding name '_ns1__checkClientVersionResponse' for type '' */
#ifndef SOAP_TYPE__ns1__checkClientVersionResponse
#define SOAP_TYPE__ns1__checkClientVersionResponse (14)
#endif

/* struct _ns1__checkClientVersion has binding name '_ns1__checkClientVersion' for type '' */
#ifndef SOAP_TYPE__ns1__checkClientVersion
#define SOAP_TYPE__ns1__checkClientVersion (13)
#endif

/* struct ns1__stPartInfo has binding name 'ns1__stPartInfo' for type 'ns1:stPartInfo' */
#ifndef SOAP_TYPE_ns1__stPartInfo
#define SOAP_TYPE_ns1__stPartInfo (12)
#endif

/* struct xsd__base64Binary has binding name 'xsd__base64Binary' for type 'xsd:base64Binary' */
#ifndef SOAP_TYPE_xsd__base64Binary
#define SOAP_TYPE_xsd__base64Binary (7)
#endif

/* struct SOAP_ENV__Reason * has binding name 'PointerToSOAP_ENV__Reason' for type '' */
#ifndef SOAP_TYPE_PointerToSOAP_ENV__Reason
#define SOAP_TYPE_PointerToSOAP_ENV__Reason (39)
#endif

/* struct SOAP_ENV__Detail * has binding name 'PointerToSOAP_ENV__Detail' for type '' */
#ifndef SOAP_TYPE_PointerToSOAP_ENV__Detail
#define SOAP_TYPE_PointerToSOAP_ENV__Detail (38)
#endif

/* struct SOAP_ENV__Code * has binding name 'PointerToSOAP_ENV__Code' for type '' */
#ifndef SOAP_TYPE_PointerToSOAP_ENV__Code
#define SOAP_TYPE_PointerToSOAP_ENV__Code (32)
#endif

/* struct _ns1__serveFilePartResponse * has binding name 'PointerTo_ns1__serveFilePartResponse' for type '' */
#ifndef SOAP_TYPE_PointerTo_ns1__serveFilePartResponse
#define SOAP_TYPE_PointerTo_ns1__serveFilePartResponse (23)
#endif

/* struct _ns1__serveFilePart * has binding name 'PointerTo_ns1__serveFilePart' for type '' */
#ifndef SOAP_TYPE_PointerTo_ns1__serveFilePart
#define SOAP_TYPE_PointerTo_ns1__serveFilePart (22)
#endif

/* struct _ns1__checkClientVersionResponse * has binding name 'PointerTo_ns1__checkClientVersionResponse' for type '' */
#ifndef SOAP_TYPE_PointerTo_ns1__checkClientVersionResponse
#define SOAP_TYPE_PointerTo_ns1__checkClientVersionResponse (19)
#endif

/* struct _ns1__checkClientVersion * has binding name 'PointerTo_ns1__checkClientVersion' for type '' */
#ifndef SOAP_TYPE_PointerTo_ns1__checkClientVersion
#define SOAP_TYPE_PointerTo_ns1__checkClientVersion (18)
#endif

/* struct ns1__stPartInfo * has binding name 'PointerTons1__stPartInfo' for type 'ns1:stPartInfo' */
#ifndef SOAP_TYPE_PointerTons1__stPartInfo
#define SOAP_TYPE_PointerTons1__stPartInfo (16)
#endif

/* unsigned char * has binding name 'PointerTounsignedByte' for type 'xsd:unsignedByte' */
#ifndef SOAP_TYPE_PointerTounsignedByte
#define SOAP_TYPE_PointerTounsignedByte (10)
#endif

/* _QName has binding name '_QName' for type 'xsd:QName' */
#ifndef SOAP_TYPE__QName
#define SOAP_TYPE__QName (6)
#endif

/* _XML has binding name '_XML' for type '' */
#ifndef SOAP_TYPE__XML
#define SOAP_TYPE__XML (5)
#endif

/* char * has binding name 'string' for type 'xsd:string' */
#ifndef SOAP_TYPE_string
#define SOAP_TYPE_string (4)
#endif

/******************************************************************************\
 *                                                                            *
 * Externals                                                                  *
 *                                                                            *
\******************************************************************************/


/******************************************************************************\
 *                                                                            *
 * Client-Side Call Stub Functions                                            *
 *                                                                            *
\******************************************************************************/

    
    /** Web service synchronous operation 'soap_call___ns1__checkClientVersion' to the specified endpoint and SOAP Action header, returns SOAP_OK or error code */
    SOAP_FMAC5 int SOAP_FMAC6 soap_call___ns1__checkClientVersion(struct soap *soap, const char *soap_endpoint, const char *soap_action, struct _ns1__checkClientVersion *ns1__checkClientVersion, struct _ns1__checkClientVersionResponse *ns1__checkClientVersionResponse);
    /** Web service asynchronous operation 'soap_send___ns1__checkClientVersion' to send a request message to the specified endpoint and SOAP Action header, returns SOAP_OK or error code */
    SOAP_FMAC5 int SOAP_FMAC6 soap_send___ns1__checkClientVersion(struct soap *soap, const char *soap_endpoint, const char *soap_action, struct _ns1__checkClientVersion *ns1__checkClientVersion);
    /** Web service asynchronous operation 'soap_recv___ns1__checkClientVersion' to receive a response message from the connected endpoint, returns SOAP_OK or error code */
    SOAP_FMAC5 int SOAP_FMAC6 soap_recv___ns1__checkClientVersion(struct soap *soap, struct _ns1__checkClientVersionResponse *ns1__checkClientVersionResponse);
    
    /** Web service synchronous operation 'soap_call___ns1__serveFilePart' to the specified endpoint and SOAP Action header, returns SOAP_OK or error code */
    SOAP_FMAC5 int SOAP_FMAC6 soap_call___ns1__serveFilePart(struct soap *soap, const char *soap_endpoint, const char *soap_action, struct _ns1__serveFilePart *ns1__serveFilePart, struct _ns1__serveFilePartResponse *ns1__serveFilePartResponse);
    /** Web service asynchronous operation 'soap_send___ns1__serveFilePart' to send a request message to the specified endpoint and SOAP Action header, returns SOAP_OK or error code */
    SOAP_FMAC5 int SOAP_FMAC6 soap_send___ns1__serveFilePart(struct soap *soap, const char *soap_endpoint, const char *soap_action, struct _ns1__serveFilePart *ns1__serveFilePart);
    /** Web service asynchronous operation 'soap_recv___ns1__serveFilePart' to receive a response message from the connected endpoint, returns SOAP_OK or error code */
    SOAP_FMAC5 int SOAP_FMAC6 soap_recv___ns1__serveFilePart(struct soap *soap, struct _ns1__serveFilePartResponse *ns1__serveFilePartResponse);
    
    /** Web service synchronous operation 'soap_call___ns1__checkClientVersion_' to the specified endpoint and SOAP Action header, returns SOAP_OK or error code */
    SOAP_FMAC5 int SOAP_FMAC6 soap_call___ns1__checkClientVersion_(struct soap *soap, const char *soap_endpoint, const char *soap_action, struct _ns1__checkClientVersion *ns1__checkClientVersion, struct _ns1__checkClientVersionResponse *ns1__checkClientVersionResponse);
    /** Web service asynchronous operation 'soap_send___ns1__checkClientVersion_' to send a request message to the specified endpoint and SOAP Action header, returns SOAP_OK or error code */
    SOAP_FMAC5 int SOAP_FMAC6 soap_send___ns1__checkClientVersion_(struct soap *soap, const char *soap_endpoint, const char *soap_action, struct _ns1__checkClientVersion *ns1__checkClientVersion);
    /** Web service asynchronous operation 'soap_recv___ns1__checkClientVersion_' to receive a response message from the connected endpoint, returns SOAP_OK or error code */
    SOAP_FMAC5 int SOAP_FMAC6 soap_recv___ns1__checkClientVersion_(struct soap *soap, struct _ns1__checkClientVersionResponse *ns1__checkClientVersionResponse);
    
    /** Web service synchronous operation 'soap_call___ns1__serveFilePart_' to the specified endpoint and SOAP Action header, returns SOAP_OK or error code */
    SOAP_FMAC5 int SOAP_FMAC6 soap_call___ns1__serveFilePart_(struct soap *soap, const char *soap_endpoint, const char *soap_action, struct _ns1__serveFilePart *ns1__serveFilePart, struct _ns1__serveFilePartResponse *ns1__serveFilePartResponse);
    /** Web service asynchronous operation 'soap_send___ns1__serveFilePart_' to send a request message to the specified endpoint and SOAP Action header, returns SOAP_OK or error code */
    SOAP_FMAC5 int SOAP_FMAC6 soap_send___ns1__serveFilePart_(struct soap *soap, const char *soap_endpoint, const char *soap_action, struct _ns1__serveFilePart *ns1__serveFilePart);
    /** Web service asynchronous operation 'soap_recv___ns1__serveFilePart_' to receive a response message from the connected endpoint, returns SOAP_OK or error code */
    SOAP_FMAC5 int SOAP_FMAC6 soap_recv___ns1__serveFilePart_(struct soap *soap, struct _ns1__serveFilePartResponse *ns1__serveFilePartResponse);

/******************************************************************************\
 *                                                                            *
 * Server-Side Operations                                                     *
 *                                                                            *
\******************************************************************************/

    /** Web service operation '__ns1__checkClientVersion' implementation, should return SOAP_OK or error code */
    SOAP_FMAC5 int SOAP_FMAC6 __ns1__checkClientVersion(struct soap*, struct _ns1__checkClientVersion *ns1__checkClientVersion, struct _ns1__checkClientVersionResponse *ns1__checkClientVersionResponse);
    /** Web service operation '__ns1__serveFilePart' implementation, should return SOAP_OK or error code */
    SOAP_FMAC5 int SOAP_FMAC6 __ns1__serveFilePart(struct soap*, struct _ns1__serveFilePart *ns1__serveFilePart, struct _ns1__serveFilePartResponse *ns1__serveFilePartResponse);
    /** Web service operation '__ns1__checkClientVersion_' implementation, should return SOAP_OK or error code */
    SOAP_FMAC5 int SOAP_FMAC6 __ns1__checkClientVersion_(struct soap*, struct _ns1__checkClientVersion *ns1__checkClientVersion, struct _ns1__checkClientVersionResponse *ns1__checkClientVersionResponse);
    /** Web service operation '__ns1__serveFilePart_' implementation, should return SOAP_OK or error code */
    SOAP_FMAC5 int SOAP_FMAC6 __ns1__serveFilePart_(struct soap*, struct _ns1__serveFilePart *ns1__serveFilePart, struct _ns1__serveFilePartResponse *ns1__serveFilePartResponse);

/******************************************************************************\
 *                                                                            *
 * Server-Side Skeletons to Invoke Service Operations                         *
 *                                                                            *
\******************************************************************************/

SOAP_FMAC5 int SOAP_FMAC6 soap_serve(struct soap*);

SOAP_FMAC5 int SOAP_FMAC6 soap_serve_request(struct soap*);

SOAP_FMAC5 int SOAP_FMAC6 soap_serve___ns1__checkClientVersion(struct soap*);

SOAP_FMAC5 int SOAP_FMAC6 soap_serve___ns1__serveFilePart(struct soap*);

SOAP_FMAC5 int SOAP_FMAC6 soap_serve___ns1__checkClientVersion_(struct soap*);

SOAP_FMAC5 int SOAP_FMAC6 soap_serve___ns1__serveFilePart_(struct soap*);

#endif

/* End of soapStub.h */