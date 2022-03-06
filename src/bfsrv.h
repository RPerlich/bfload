/* bfsrv.h
   Generated by wsdl2h 2.8.119 from serveBFService.wsdl and typemap.dat
   2022-02-15 21:45:38 GMT

   DO NOT INCLUDE THIS ANNOTATED FILE DIRECTLY IN YOUR PROJECT SOURCE CODE.
   USE THE FILES GENERATED BY soapcpp2 FOR YOUR PROJECT'S SOURCE CODE.

gSOAP XML Web services tools
Copyright (C) 2000-2021, Robert van Engelen, Genivia Inc. All Rights Reserved.
This program is released under the GPL with the additional exemption that
compiling, linking, and/or using OpenSSL is allowed.
--------------------------------------------------------------------------------
A commercial use license is available from Genivia Inc., contact@genivia.com
--------------------------------------------------------------------------------
*/

/**

@page page_notes Notes

@note HINTS:
 - Run soapcpp2 on bfsrv.h to generate the SOAP/XML processing logic:
   Use soapcpp2 -I to specify paths for #import
   Use soapcpp2 -j to generate improved proxy and server classes.
   Use soapcpp2 -r to generate a report.
 - Edit 'typemap.dat' to control namespace bindings and type mappings:
   It is strongly recommended to customize the names of the namespace prefixes
   generated by wsdl2h. To do so, modify the prefix bindings in the Namespaces
   section below and add the modified lines to 'typemap.dat' to rerun wsdl2h.
 - Run Doxygen (www.doxygen.org) on this file to generate documentation.
 - Use wsdl2h -c to generate pure C code.
 - Use wsdl2h -R to include the REST operations defined by the WSDLs.
 - Use wsdl2h -O3 or -O4 to optimize by removing unused schema components.
 - Use wsdl2h -d to enable DOM support for xsd:any and xsd:anyType.
 - Use wsdl2h -F to simulate struct-type derivation in C (also works in C++).
 - Use wsdl2h -f to generate flat C++ class hierarchy, removes type derivation.
 - Use wsdl2h -g to generate top-level root elements with readers and writers.
 - Use wsdl2h -U to map XML names to C++ Unicode identifiers instead of _xNNNN.
 - Use wsdl2h -u to disable the generation of unions.
 - Use wsdl2h -L to remove this @note and all other @note comments.
 - Use wsdl2h -nname to use name as the base namespace prefix instead of 'ns'.
 - Use wsdl2h -Nname for service prefix and produce multiple service bindings
 - Struct/class members serialized as XML attributes are annotated with a '@'.
 - Struct/class members that have a special role are annotated with a '$'.

@warning
   DO NOT INCLUDE THIS ANNOTATED FILE DIRECTLY IN YOUR PROJECT SOURCE CODE.
   USE THE FILES GENERATED BY soapcpp2 FOR YOUR PROJECT'S SOURCE CODE:
   THE GENERATED soapStub.h FILE CONTAINS THIS CONTENT WITHOUT ANNOTATIONS.

@copyright LICENSE:
@verbatim
--------------------------------------------------------------------------------
gSOAP XML Web services tools
Copyright (C) 2000-2021, Robert van Engelen, Genivia Inc. All Rights Reserved.
The wsdl2h tool and its generated software are released under the GPL.
This software is released under the GPL with the additional exemption that
compiling, linking, and/or using OpenSSL is allowed.
--------------------------------------------------------------------------------
GPL license.

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program; if not, write to the Free Software Foundation, Inc., 59 Temple
Place, Suite 330, Boston, MA 02111-1307 USA

Author contact information:
engelen@genivia.com / engelen@acm.org

This program is released under the GPL with the additional exemption that
compiling, linking, and/or using OpenSSL is allowed.
--------------------------------------------------------------------------------
A commercial-use license is available from Genivia, Inc., contact@genivia.com
--------------------------------------------------------------------------------
@endverbatim

*/


//gsoapopt c,w

/******************************************************************************\
 *                                                                            *
 * Definitions                                                                *
 *   http://onsite.it-solutions.atos.net/webservices                          *
 *                                                                            *
\******************************************************************************/


/******************************************************************************\
 *                                                                            *
 * $SIZE typemap variable:                                                    *
 *   int                                                                      *
 *                                                                            *
\******************************************************************************/


/******************************************************************************\
 *                                                                            *
 * Import                                                                     *
 *                                                                            *
\******************************************************************************/


/******************************************************************************\
 *                                                                            *
 * Schema Namespaces                                                          *
 *                                                                            *
\******************************************************************************/


/* NOTE:

It is strongly recommended to customize the names of the namespace prefixes
generated by wsdl2h. To do so, modify the prefix bindings below and add the
modified lines to 'typemap.dat' then rerun wsdl2h (use wsdl2h -t typemap.dat):

ns1 = "http://onsite.it-solutions.atos.net/webservices"

*/

#define SOAP_NAMESPACE_OF_ns1	"http://onsite.it-solutions.atos.net/webservices"
//gsoap ns1   schema namespace:	http://onsite.it-solutions.atos.net/webservices
//gsoap ns1   schema elementForm:	qualified
//gsoap ns1   schema attributeForm:	unqualified

/******************************************************************************\
 *                                                                            *
 * Built-in Schema Types and Top-Level Elements and Attributes                *
 *                                                                            *
\******************************************************************************/

/// Built-in type "xs:base64Binary".
struct xsd__base64Binary
{
    unsigned char *__ptr;
    int __size;
    char *id, *type, *options; // NOTE: non-NULL for DIME/MIME/MTOM XOP attachments only
};

/// Built-in type "xs:boolean".
enum xsd__boolean { xsd__boolean__false_, xsd__boolean__true_ };



/******************************************************************************\
 *                                                                            *
 * Schema Types and Top-Level Elements and Attributes                         *
 *   http://onsite.it-solutions.atos.net/webservices                          *
 *                                                                            *
\******************************************************************************/


/******************************************************************************\
 *                                                                            *
 * Schema Complex Types and Top-Level Elements                                *
 *   http://onsite.it-solutions.atos.net/webservices                          *
 *                                                                            *
\******************************************************************************/

/// @brief "http://onsite.it-solutions.atos.net/webservices":stPartInfo is a complexType.
///
/// @note struct ns1__stPartInfo operations:
/// - ns1__stPartInfo* soap_new_ns1__stPartInfo(struct soap*, int num) allocate and default initialize one or more values (an array)
/// - soap_default_ns1__stPartInfo(struct soap*, ns1__stPartInfo*) default initialize members
/// - int soap_read_ns1__stPartInfo(struct soap*, ns1__stPartInfo*) deserialize from a source
/// - int soap_write_ns1__stPartInfo(struct soap*, ns1__stPartInfo*) serialize to a sink
/// - ns1__stPartInfo* soap_dup_ns1__stPartInfo(struct soap*, ns1__stPartInfo* dst, ns1__stPartInfo *src) returns deep copy of ns1__stPartInfo src into dst, copies the (cyclic) graph structure when a context is provided, or (cycle-pruned) tree structure with soap_set_mode(soap, SOAP_XML_TREE) (use soapcpp2 -Ec)
/// - soap_del_ns1__stPartInfo(ns1__stPartInfo*) deep deletes ns1__stPartInfo data members, use only on dst after soap_dup_ns1__stPartInfo(NULL, ns1__stPartInfo *dst, ns1__stPartInfo *src) (use soapcpp2 -Ed)
struct ns1__stPartInfo
{
/// Element "sPartName" of type xs:string.
    char*                                sPartName                      0;	///< Optional element.
/// Element "sPartFolder" of type xs:string.
    char*                                sPartFolder                    0;	///< Optional element.
/// Element "sClientVersion" of type xs:string.
    char*                                sClientVersion                 0;	///< Optional element.
};

/// @brief Top-level root element "http://onsite.it-solutions.atos.net/webservices":checkClientVersion
/// @brief "http://onsite.it-solutions.atos.net/webservices":checkClientVersion is a complexType.
///
/// @note struct _ns1__checkClientVersion operations:
/// - _ns1__checkClientVersion* soap_new__ns1__checkClientVersion(struct soap*, int num) allocate and default initialize one or more values (an array)
/// - soap_default__ns1__checkClientVersion(struct soap*, _ns1__checkClientVersion*) default initialize members
/// - int soap_read__ns1__checkClientVersion(struct soap*, _ns1__checkClientVersion*) deserialize from a source
/// - int soap_write__ns1__checkClientVersion(struct soap*, _ns1__checkClientVersion*) serialize to a sink
/// - _ns1__checkClientVersion* soap_dup__ns1__checkClientVersion(struct soap*, _ns1__checkClientVersion* dst, _ns1__checkClientVersion *src) returns deep copy of _ns1__checkClientVersion src into dst, copies the (cyclic) graph structure when a context is provided, or (cycle-pruned) tree structure with soap_set_mode(soap, SOAP_XML_TREE) (use soapcpp2 -Ec)
/// - soap_del__ns1__checkClientVersion(_ns1__checkClientVersion*) deep deletes _ns1__checkClientVersion data members, use only on dst after soap_dup__ns1__checkClientVersion(NULL, _ns1__checkClientVersion *dst, _ns1__checkClientVersion *src) (use soapcpp2 -Ed)
struct _ns1__checkClientVersion
{
/// Element "sClientVersion" of type xs:string.
    char*                                sClientVersion                 0;	///< Optional element.
};

/// @brief Top-level root element "http://onsite.it-solutions.atos.net/webservices":checkClientVersionResponse
/// @brief "http://onsite.it-solutions.atos.net/webservices":checkClientVersionResponse is a complexType.
///
/// @note struct _ns1__checkClientVersionResponse operations:
/// - _ns1__checkClientVersionResponse* soap_new__ns1__checkClientVersionResponse(struct soap*, int num) allocate and default initialize one or more values (an array)
/// - soap_default__ns1__checkClientVersionResponse(struct soap*, _ns1__checkClientVersionResponse*) default initialize members
/// - int soap_read__ns1__checkClientVersionResponse(struct soap*, _ns1__checkClientVersionResponse*) deserialize from a source
/// - int soap_write__ns1__checkClientVersionResponse(struct soap*, _ns1__checkClientVersionResponse*) serialize to a sink
/// - _ns1__checkClientVersionResponse* soap_dup__ns1__checkClientVersionResponse(struct soap*, _ns1__checkClientVersionResponse* dst, _ns1__checkClientVersionResponse *src) returns deep copy of _ns1__checkClientVersionResponse src into dst, copies the (cyclic) graph structure when a context is provided, or (cycle-pruned) tree structure with soap_set_mode(soap, SOAP_XML_TREE) (use soapcpp2 -Ec)
/// - soap_del__ns1__checkClientVersionResponse(_ns1__checkClientVersionResponse*) deep deletes _ns1__checkClientVersionResponse data members, use only on dst after soap_dup__ns1__checkClientVersionResponse(NULL, _ns1__checkClientVersionResponse *dst, _ns1__checkClientVersionResponse *src) (use soapcpp2 -Ed)
struct _ns1__checkClientVersionResponse
{
/// Element "checkClientVersionResult" of type xs:boolean.
    enum xsd__boolean                    checkClientVersionResult       1;	///< Required element.
};

/// @brief Top-level root element "http://onsite.it-solutions.atos.net/webservices":serveFilePart
/// @brief "http://onsite.it-solutions.atos.net/webservices":serveFilePart is a complexType.
///
/// @note struct _ns1__serveFilePart operations:
/// - _ns1__serveFilePart* soap_new__ns1__serveFilePart(struct soap*, int num) allocate and default initialize one or more values (an array)
/// - soap_default__ns1__serveFilePart(struct soap*, _ns1__serveFilePart*) default initialize members
/// - int soap_read__ns1__serveFilePart(struct soap*, _ns1__serveFilePart*) deserialize from a source
/// - int soap_write__ns1__serveFilePart(struct soap*, _ns1__serveFilePart*) serialize to a sink
/// - _ns1__serveFilePart* soap_dup__ns1__serveFilePart(struct soap*, _ns1__serveFilePart* dst, _ns1__serveFilePart *src) returns deep copy of _ns1__serveFilePart src into dst, copies the (cyclic) graph structure when a context is provided, or (cycle-pruned) tree structure with soap_set_mode(soap, SOAP_XML_TREE) (use soapcpp2 -Ec)
/// - soap_del__ns1__serveFilePart(_ns1__serveFilePart*) deep deletes _ns1__serveFilePart data members, use only on dst after soap_dup__ns1__serveFilePart(NULL, _ns1__serveFilePart *dst, _ns1__serveFilePart *src) (use soapcpp2 -Ed)
struct _ns1__serveFilePart
{
/// Element "partInfo" of type "http://onsite.it-solutions.atos.net/webservices":stPartInfo.
    struct ns1__stPartInfo*              partInfo                       1;	///< Required element.
};

/// @brief Top-level root element "http://onsite.it-solutions.atos.net/webservices":serveFilePartResponse
/// @brief "http://onsite.it-solutions.atos.net/webservices":serveFilePartResponse is a complexType.
///
/// @note struct _ns1__serveFilePartResponse operations:
/// - _ns1__serveFilePartResponse* soap_new__ns1__serveFilePartResponse(struct soap*, int num) allocate and default initialize one or more values (an array)
/// - soap_default__ns1__serveFilePartResponse(struct soap*, _ns1__serveFilePartResponse*) default initialize members
/// - int soap_read__ns1__serveFilePartResponse(struct soap*, _ns1__serveFilePartResponse*) deserialize from a source
/// - int soap_write__ns1__serveFilePartResponse(struct soap*, _ns1__serveFilePartResponse*) serialize to a sink
/// - _ns1__serveFilePartResponse* soap_dup__ns1__serveFilePartResponse(struct soap*, _ns1__serveFilePartResponse* dst, _ns1__serveFilePartResponse *src) returns deep copy of _ns1__serveFilePartResponse src into dst, copies the (cyclic) graph structure when a context is provided, or (cycle-pruned) tree structure with soap_set_mode(soap, SOAP_XML_TREE) (use soapcpp2 -Ec)
/// - soap_del__ns1__serveFilePartResponse(_ns1__serveFilePartResponse*) deep deletes _ns1__serveFilePartResponse data members, use only on dst after soap_dup__ns1__serveFilePartResponse(NULL, _ns1__serveFilePartResponse *dst, _ns1__serveFilePartResponse *src) (use soapcpp2 -Ed)
struct _ns1__serveFilePartResponse
{
/// Element "serveFilePartResult" of type xs:base64Binary.
    struct xsd__base64Binary             serveFilePartResult            0;	///< Optional element.
};


/******************************************************************************\
 *                                                                            *
 * Additional Top-Level Elements                                              *
 *   http://onsite.it-solutions.atos.net/webservices                          *
 *                                                                            *
\******************************************************************************/


/******************************************************************************\
 *                                                                            *
 * Additional Top-Level Attributes                                            *
 *   http://onsite.it-solutions.atos.net/webservices                          *
 *                                                                            *
\******************************************************************************/


/******************************************************************************\
 *                                                                            *
 * Services                                                                   *
 *                                                                            *
\******************************************************************************/

// This service supports SOAP 1.2 namespaces:
#import "soap12.h"

//gsoap ns1  service name:	serveBFServiceSoap 
//gsoap ns1  service type:	serveBFServiceSoap 
//gsoap ns1  service port:	https://onsite.it-solutions.atos.net/BFService/serveBFService.asmx 
//gsoap ns1  service namespace:	http://onsite.it-solutions.atos.net/webservices 
//gsoap ns1  service transport:	http://schemas.xmlsoap.org/soap/http 

/** @mainpage Service Definitions

@section Service_bindings Service Bindings

  - @ref serveBFServiceSoap

@section Service_more More Information

  - @ref page_notes "Notes"

  - @ref page_XMLDataBinding "XML Data Binding"

  - @ref SOAP_ENV__Header "SOAP Header Content" (when applicable)

  - @ref SOAP_ENV__Detail "SOAP Fault Detail Content" (when applicable)


*/

/** @page serveBFServiceSoap Binding "serveBFServiceSoap"

@section serveBFServiceSoap_operations Operations of Binding "serveBFServiceSoap"

  - @ref __ns1__checkClientVersion

  - @ref __ns1__serveFilePart

  - @ref __ns1__checkClientVersion_

  - @ref __ns1__serveFilePart_

@section serveBFServiceSoap_ports Default endpoints of Binding "serveBFServiceSoap"

  - https://onsite.it-solutions.atos.net/BFService/serveBFService.asmx

@note Multiple service bindings collected as one, use wsdl2h option -Nname to produce a separate service for each binding


*/

/******************************************************************************\
 *                                                                            *
 * Service Binding                                                            *
 *   serveBFServiceSoap                                                       *
 *                                                                            *
\******************************************************************************/


/******************************************************************************\
 *                                                                            *
 * Service Operation                                                          *
 *   __ns1__checkClientVersion                                                *
 *                                                                            *
\******************************************************************************/


/** Operation "__ns1__checkClientVersion" of service binding "serveBFServiceSoap".
Check if the version of the used client is correct.

  - SOAP document/literal style messaging

  - Default endpoints:
    - https://onsite.it-solutions.atos.net/BFService/serveBFService.asmx

  - Default SOAP action or REST location path:
    - "http://onsite.it-solutions.atos.net/webservices/checkClientVersion"

  - Addressing input action: "http://onsite.it-solutions.atos.net/webservices/checkClientVersion"

  - Addressing output action: "http://onsite.it-solutions.atos.net/webservices/checkClientVersionResponse"

C stub function (defined in soapClient.c[pp] generated by soapcpp2):
@code
  int soap_call___ns1__checkClientVersion(
    struct soap *soap,
    NULL, // char *endpoint = NULL selects default endpoint for this operation
    NULL, // char *action = NULL selects default action for this operation
    // input parameters:
    struct _ns1__checkClientVersion*    ns1__checkClientVersion,
    // output parameters:
    struct _ns1__checkClientVersionResponse*ns1__checkClientVersionResponse
  );
@endcode

C server function (called from the service dispatcher defined in soapServer.c[pp]):
@code
  int __ns1__checkClientVersion(
    struct soap *soap,
    // input parameters:
    struct _ns1__checkClientVersion*    ns1__checkClientVersion,
    // output parameters:
    struct _ns1__checkClientVersionResponse*ns1__checkClientVersionResponse
  );
@endcode

*/

//gsoap ns1  service method-protocol:	checkClientVersion SOAP
//gsoap ns1  service method-style:	checkClientVersion document
//gsoap ns1  service method-encoding:	checkClientVersion literal
//gsoap ns1  service method-input-action:	checkClientVersion http://onsite.it-solutions.atos.net/webservices/checkClientVersion
//gsoap ns1  service method-output-action:	checkClientVersion http://onsite.it-solutions.atos.net/webservices/checkClientVersionResponse
int __ns1__checkClientVersion(
    struct _ns1__checkClientVersion*    ns1__checkClientVersion,	///< Input parameter
    struct _ns1__checkClientVersionResponse*ns1__checkClientVersionResponse	///< Output parameter
);

/******************************************************************************\
 *                                                                            *
 * Service Operation                                                          *
 *   __ns1__serveFilePart                                                     *
 *                                                                            *
\******************************************************************************/


/** Operation "__ns1__serveFilePart" of service binding "serveBFServiceSoap".
Serve a part of a file to the client.

  - SOAP document/literal style messaging

  - Default endpoints:
    - https://onsite.it-solutions.atos.net/BFService/serveBFService.asmx

  - Default SOAP action or REST location path:
    - "http://onsite.it-solutions.atos.net/webservices/serveFilePart"

  - Addressing input action: "http://onsite.it-solutions.atos.net/webservices/serveFilePart"

  - Addressing output action: "http://onsite.it-solutions.atos.net/webservices/serveFilePartResponse"

C stub function (defined in soapClient.c[pp] generated by soapcpp2):
@code
  int soap_call___ns1__serveFilePart(
    struct soap *soap,
    NULL, // char *endpoint = NULL selects default endpoint for this operation
    NULL, // char *action = NULL selects default action for this operation
    // input parameters:
    struct _ns1__serveFilePart*         ns1__serveFilePart,
    // output parameters:
    struct _ns1__serveFilePartResponse *ns1__serveFilePartResponse
  );
@endcode

C server function (called from the service dispatcher defined in soapServer.c[pp]):
@code
  int __ns1__serveFilePart(
    struct soap *soap,
    // input parameters:
    struct _ns1__serveFilePart*         ns1__serveFilePart,
    // output parameters:
    struct _ns1__serveFilePartResponse *ns1__serveFilePartResponse
  );
@endcode

*/

//gsoap ns1  service method-protocol:	serveFilePart SOAP
//gsoap ns1  service method-style:	serveFilePart document
//gsoap ns1  service method-encoding:	serveFilePart literal
//gsoap ns1  service method-input-action:	serveFilePart http://onsite.it-solutions.atos.net/webservices/serveFilePart
//gsoap ns1  service method-output-action:	serveFilePart http://onsite.it-solutions.atos.net/webservices/serveFilePartResponse
int __ns1__serveFilePart(
    struct _ns1__serveFilePart*         ns1__serveFilePart,	///< Input parameter
    struct _ns1__serveFilePartResponse *ns1__serveFilePartResponse	///< Output parameter
);

/******************************************************************************\
 *                                                                            *
 * Service Operation                                                          *
 *   __ns1__checkClientVersion_                                               *
 *                                                                            *
\******************************************************************************/


/** Operation "__ns1__checkClientVersion_" of service binding "serveBFServiceSoap".
Check if the version of the used client is correct.

  - SOAP document/literal style messaging

  - Default endpoints:
    - https://onsite.it-solutions.atos.net/BFService/serveBFService.asmx

  - Default SOAP action or REST location path:
    - "http://onsite.it-solutions.atos.net/webservices/checkClientVersion"

  - Addressing input action: "http://onsite.it-solutions.atos.net/webservices/checkClientVersion"

  - Addressing output action: "http://onsite.it-solutions.atos.net/webservices/checkClientVersionResponse"

C stub function (defined in soapClient.c[pp] generated by soapcpp2):
@code
  int soap_call___ns1__checkClientVersion_(
    struct soap *soap,
    NULL, // char *endpoint = NULL selects default endpoint for this operation
    NULL, // char *action = NULL selects default action for this operation
    // input parameters:
    struct _ns1__checkClientVersion*    ns1__checkClientVersion,
    // output parameters:
    struct _ns1__checkClientVersionResponse*ns1__checkClientVersionResponse
  );
@endcode

C server function (called from the service dispatcher defined in soapServer.c[pp]):
@code
  int __ns1__checkClientVersion_(
    struct soap *soap,
    // input parameters:
    struct _ns1__checkClientVersion*    ns1__checkClientVersion,
    // output parameters:
    struct _ns1__checkClientVersionResponse*ns1__checkClientVersionResponse
  );
@endcode

*/

//gsoap ns1  service method-protocol:	checkClientVersion_ SOAP
//gsoap ns1  service method-style:	checkClientVersion_ document
//gsoap ns1  service method-encoding:	checkClientVersion_ literal
//gsoap ns1  service method-input-action:	checkClientVersion_ http://onsite.it-solutions.atos.net/webservices/checkClientVersion
//gsoap ns1  service method-output-action:	checkClientVersion_ http://onsite.it-solutions.atos.net/webservices/checkClientVersionResponse
int __ns1__checkClientVersion_(
    struct _ns1__checkClientVersion*    ns1__checkClientVersion,	///< Input parameter
    struct _ns1__checkClientVersionResponse*ns1__checkClientVersionResponse	///< Output parameter
);

/******************************************************************************\
 *                                                                            *
 * Service Operation                                                          *
 *   __ns1__serveFilePart_                                                    *
 *                                                                            *
\******************************************************************************/


/** Operation "__ns1__serveFilePart_" of service binding "serveBFServiceSoap".
Serve a part of a file to the client.

  - SOAP document/literal style messaging

  - Default endpoints:
    - https://onsite.it-solutions.atos.net/BFService/serveBFService.asmx

  - Default SOAP action or REST location path:
    - "http://onsite.it-solutions.atos.net/webservices/serveFilePart"

  - Addressing input action: "http://onsite.it-solutions.atos.net/webservices/serveFilePart"

  - Addressing output action: "http://onsite.it-solutions.atos.net/webservices/serveFilePartResponse"

C stub function (defined in soapClient.c[pp] generated by soapcpp2):
@code
  int soap_call___ns1__serveFilePart_(
    struct soap *soap,
    NULL, // char *endpoint = NULL selects default endpoint for this operation
    NULL, // char *action = NULL selects default action for this operation
    // input parameters:
    struct _ns1__serveFilePart*         ns1__serveFilePart,
    // output parameters:
    struct _ns1__serveFilePartResponse *ns1__serveFilePartResponse
  );
@endcode

C server function (called from the service dispatcher defined in soapServer.c[pp]):
@code
  int __ns1__serveFilePart_(
    struct soap *soap,
    // input parameters:
    struct _ns1__serveFilePart*         ns1__serveFilePart,
    // output parameters:
    struct _ns1__serveFilePartResponse *ns1__serveFilePartResponse
  );
@endcode

*/

//gsoap ns1  service method-protocol:	serveFilePart_ SOAP
//gsoap ns1  service method-style:	serveFilePart_ document
//gsoap ns1  service method-encoding:	serveFilePart_ literal
//gsoap ns1  service method-input-action:	serveFilePart_ http://onsite.it-solutions.atos.net/webservices/serveFilePart
//gsoap ns1  service method-output-action:	serveFilePart_ http://onsite.it-solutions.atos.net/webservices/serveFilePartResponse
int __ns1__serveFilePart_(
    struct _ns1__serveFilePart*         ns1__serveFilePart,	///< Input parameter
    struct _ns1__serveFilePartResponse *ns1__serveFilePartResponse	///< Output parameter
);

/** @page serveBFServiceSoap Binding "serveBFServiceSoap"

@section serveBFServiceSoap_policy_enablers Policy Enablers of Binding "serveBFServiceSoap"

None specified.

*/

/******************************************************************************\
 *                                                                            *
 * XML Data Binding                                                           *
 *                                                                            *
\******************************************************************************/


/** @page page_XMLDataBinding XML Data Binding

SOAP/XML services use data bindings that are contractually bound by WSDLs and
are auto-generated by wsdl2h and soapcpp2 (see Service Bindings). Plain data
bindings are adopted from XML schemas as part of the WSDL types section or when
running wsdl2h on a set of schemas to produce non-SOAP-based XML data bindings.

@note The following readers and writers are C/C++ data type (de)serializers
auto-generated by wsdl2h and soapcpp2. Run soapcpp2 on this file to generate the
(de)serialization code, which is stored in soapC.c[pp]. Include "soapH.h" in
your code to import these data type and function declarations. Only use the
soapcpp2-generated files in your project build. Do not include the wsdl2h-
generated .h file in your code.

@note Data can be read and deserialized from:
  - an int file descriptor, using soap->recvfd = fd
  - a socket, using soap->socket = (int)...
  - a C++ stream (istream, stringstream), using soap->is = (istream*)...
  - a C string, using soap->is = (const char*)...
  - any input, using the soap->frecv() callback

@note Data can be serialized and written to:
  - an int file descriptor, using soap->sendfd = (int)...
  - a socket, using soap->socket = (int)...
  - a C++ stream (ostream, stringstream), using soap->os = (ostream*)...
  - a C string, using soap->os = (const char**)...
  - any output, using the soap->fsend() callback

@note The following options are available for (de)serialization control:
  - soap->encodingStyle = NULL; to remove SOAP 1.1/1.2 encodingStyle
  - soap_set_mode(soap, SOAP_XML_TREE); XML without id-ref (no cycles!)
  - soap_set_mode(soap, SOAP_XML_GRAPH); XML with id-ref (including cycles)
  - soap_set_namespaces(soap, struct Namespace *nsmap); to set xmlns bindings


*/

/**

@section ns1 Top-level root elements of schema "http://onsite.it-solutions.atos.net/webservices"

  - <ns1:checkClientVersion> @ref _ns1__checkClientVersion
    @code
    // Reader (returns SOAP_OK on success):
    soap_read__ns1__checkClientVersion(struct soap*, struct _ns1__checkClientVersion*);
    // Writer (returns SOAP_OK on success):
    soap_write__ns1__checkClientVersion(struct soap*, struct _ns1__checkClientVersion*);
    // REST GET (returns SOAP_OK on success):
    soap_GET__ns1__checkClientVersion(struct soap*, const char *URL, struct _ns1__checkClientVersion*);
    // REST PUT (returns SOAP_OK on success):
    soap_PUT__ns1__checkClientVersion(struct soap*, const char *URL, struct _ns1__checkClientVersion*);
    // REST POST (returns SOAP_OK on success):
    soap_POST_send__ns1__checkClientVersion(struct soap*, const char *URL, struct _ns1__checkClientVersion*);
    soap_POST_recv__ns1__checkClientVersion(struct soap*, struct _ns1__checkClientVersion*);
    @endcode

  - <ns1:checkClientVersionResponse> @ref _ns1__checkClientVersionResponse
    @code
    // Reader (returns SOAP_OK on success):
    soap_read__ns1__checkClientVersionResponse(struct soap*, struct _ns1__checkClientVersionResponse*);
    // Writer (returns SOAP_OK on success):
    soap_write__ns1__checkClientVersionResponse(struct soap*, struct _ns1__checkClientVersionResponse*);
    // REST GET (returns SOAP_OK on success):
    soap_GET__ns1__checkClientVersionResponse(struct soap*, const char *URL, struct _ns1__checkClientVersionResponse*);
    // REST PUT (returns SOAP_OK on success):
    soap_PUT__ns1__checkClientVersionResponse(struct soap*, const char *URL, struct _ns1__checkClientVersionResponse*);
    // REST POST (returns SOAP_OK on success):
    soap_POST_send__ns1__checkClientVersionResponse(struct soap*, const char *URL, struct _ns1__checkClientVersionResponse*);
    soap_POST_recv__ns1__checkClientVersionResponse(struct soap*, struct _ns1__checkClientVersionResponse*);
    @endcode

  - <ns1:serveFilePart> @ref _ns1__serveFilePart
    @code
    // Reader (returns SOAP_OK on success):
    soap_read__ns1__serveFilePart(struct soap*, struct _ns1__serveFilePart*);
    // Writer (returns SOAP_OK on success):
    soap_write__ns1__serveFilePart(struct soap*, struct _ns1__serveFilePart*);
    // REST GET (returns SOAP_OK on success):
    soap_GET__ns1__serveFilePart(struct soap*, const char *URL, struct _ns1__serveFilePart*);
    // REST PUT (returns SOAP_OK on success):
    soap_PUT__ns1__serveFilePart(struct soap*, const char *URL, struct _ns1__serveFilePart*);
    // REST POST (returns SOAP_OK on success):
    soap_POST_send__ns1__serveFilePart(struct soap*, const char *URL, struct _ns1__serveFilePart*);
    soap_POST_recv__ns1__serveFilePart(struct soap*, struct _ns1__serveFilePart*);
    @endcode

  - <ns1:serveFilePartResponse> @ref _ns1__serveFilePartResponse
    @code
    // Reader (returns SOAP_OK on success):
    soap_read__ns1__serveFilePartResponse(struct soap*, struct _ns1__serveFilePartResponse*);
    // Writer (returns SOAP_OK on success):
    soap_write__ns1__serveFilePartResponse(struct soap*, struct _ns1__serveFilePartResponse*);
    // REST GET (returns SOAP_OK on success):
    soap_GET__ns1__serveFilePartResponse(struct soap*, const char *URL, struct _ns1__serveFilePartResponse*);
    // REST PUT (returns SOAP_OK on success):
    soap_PUT__ns1__serveFilePartResponse(struct soap*, const char *URL, struct _ns1__serveFilePartResponse*);
    // REST POST (returns SOAP_OK on success):
    soap_POST_send__ns1__serveFilePartResponse(struct soap*, const char *URL, struct _ns1__serveFilePartResponse*);
    soap_POST_recv__ns1__serveFilePartResponse(struct soap*, struct _ns1__serveFilePartResponse*);
    @endcode

*/

/* End of bfsrv.h */