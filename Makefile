t:
	gcc -O4 sf.c test.c -o test -lev

lib: 
	gcc -g -shared sf.c -o libsf.so -lev -fPIC
	cp libsf.so /usr/local/lib/libsf.so

all: lib t
