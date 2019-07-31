AUTOMAKE_OPTIONS = gnu
SUBDIRS=src tests

cppcheck:
	cppcheck --enable=all $(top_srcdir)
	
count:
	sloccount $(top_srcdir)/src 
	

