sbin_PROGRAMS=fuse_xattrs

fuse_xattrs_SOURCES = fuse_xattrs.c
fuse_xattrs_SOURCES += binary_storage.c  binary_storage.h
fuse_xattrs_SOURCES += passthrough.c  passthrough.h
fuse_xattrs_SOURCES += utils.c  utils.h
fuse_xattrs_SOURCES += xattrs_config.h fuse_xattrs_config.h
fuse_xattrs_SOURCES += debug.h debug.cpp

fuse_xattrs_CPPFLAGS =-D_SCM_LABEL="$(SCM_LABEL)"
fuse_xattrs_CPPFLAGS +=-D_CONFIGDIR="$(sysconfdir)"
fuse_xattrs_CPPFLAGS += `pkg-config --cflags fuse`
fuse_xattrs_CPPFLAGS += -I$(top_srcdir)

fuse_xattrs_CXXFLAGS = -Wall -Wextra -Wformat
#fuse_xattrs_CXXFLAGS += -Wconversion -Winline  
fuse_xattrs_CXXFLAGS += -Wmissing-include-dirs -Wmissing-noreturn  -Wpacked  -Wparentheses
fuse_xattrs_CXXFLAGS += -Wpointer-arith -Wformat-nonliteral -Winit-self -Wwrite-strings
fuse_xattrs_CXXFLAGS += -Wmissing-braces  -Wmissing-field-initializers -Wmissing-format-attribute
fuse_xattrs_CXXFLAGS += -Wcast-qual -Wfloat-equal -Wshadow
fuse_xattrs_CXXFLAGS += -fstack-protector -Wl,-z,relro -Wl,-z,now -Wformat-security  

fuse_xattrs_LDFLAGS = `pkg-config --libs fuse` 
fuse_xattrs_LDFLAGS += -fPIE -flto -Wl,--build-id=sha1 -rdynamic
