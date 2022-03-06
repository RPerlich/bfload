bin_PROGRAMS = bfload
AM_LDFLAGS = -L/usr/lib
AM_CXXFLAGS = -DNDEBUG -Wall -Wextra -DWITH_CURL
bfload_CFLAGS = -I/usr/include/libxml2
bfload_SOURCES = \
	bfsrv.h \
	serveBFServiceSoap.nsmap \
	rp_base64.h \
	rp_base64.c \
	rp_sha256.h \
	rp_sha256.c \
	rp_str_list.h \
	rp_str_list.c \
	rp_tools.h \
	rp_tools.c \
	curlapi.h \
	curlapi.c \
	stdsoap2.h \
	stdsoap2.c \
	soapStub.h \
	soapH.h \
	soapC.c \
	soapClient.c \
	bfload.c
bfload_LDADD= -lxml2 -lcurl -lssl -lcrypto

