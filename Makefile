t:
	gcc -O4 test.c -o test -lev -lsf

lib: 
	gcc -g -shared sf.c -o libsf.so -lev -fPIC
	cp libsf.so /usr/local/lib/
	cp sf.h /usr/local/include/
	ldconfig

all: lib t
