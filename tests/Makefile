all:  basic \
			meng-thesis-example \
			array-overflow \
			array-param \
			struct-basic \
			globals

all-traces: basic.trace \
						meng-thesis-example.trace \
						array-overflow.trace \
						array-param.trace \
						struct-basic.trace \
						globals.trace


%: %.c
	gcc -ggdb -O0 -fno-omit-frame-pointer $< -o $@

%.trace: % ../valgrind-3.11.0/inst/bin/valgrind
	# always return 'success' to keep 'make' running even on errors
	../valgrind-3.11.0/inst/bin/valgrind --tool=memcheck --source-filename=$<.c --trace-filename=$<.trace ./$< || true
