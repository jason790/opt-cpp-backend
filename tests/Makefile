all: basic meng-thesis-example array-overflow array-param

%: %.c
	gcc -ggdb -O0 -fno-omit-frame-pointer $< -o $@

val:
	../valgrind-3.11.0/inst/bin/valgrind --tool=memcheck --source-filename=$(prog).c ./$(prog)