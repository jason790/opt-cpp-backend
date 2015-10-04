all: basic meng-thesis-example array-overflow array-param struct-basic globals

%: %.c
	gcc -ggdb -O0 -fno-omit-frame-pointer $< -o $@

val:
	../valgrind-3.11.0/inst/bin/valgrind --tool=memcheck --source-filename=$(prog).c --trace-filename=$(prog).vgtrace ./$(prog)
