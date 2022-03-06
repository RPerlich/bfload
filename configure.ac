AC_INIT([bfload], [0.6.0], [rp990@maibox.org])
AC_CONFIG_HEADERS(src/config.h)
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_FILES([Makefile src/Makefile])
AC_PROG_CC

# checking for openssl
PKG_CHECK_MODULES([OPENSSL], [openssl >= 0.9.8], [],
  [AC_MSG_ERROR([please install libssl-dev or openssl-devel])])

# look for openssl binary
OPENSSL_BIN=`$PKG_CONFIG --variable=exec_prefix openssl`/bin
AC_PATH_PROGS([OPENSSL], [openssl], [:], [$OPENSSL_BIN:$PATH])

# checking for libxml2
PKG_CHECK_MODULES([XML2], [libxml-2.0], [],
	[AC_MSG_ERROR([please install libxml2 and libxml2-dev])])

# checking for libcurl	
PKG_CHECK_MODULES([CURL], [libcurl], [],
	[AC_MSG_ERROR([please install curl])])
	
AC_OUTPUT

echo ""
echo "bfload will be compiled with:"
echo "  CFLAGS = $CFLAGS"
echo "  LDFLAGS = $LDFLAGS"
echo "  prefix = $prefix"
echo "  exec_prefix = $exec_prefix"
echo "  libdir = $libdir"
echo "  bindir = $bindir"
