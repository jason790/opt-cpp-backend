all:  basic \
			meng-thesis-example \
			array-overflow \
			array-param \
			struct-basic \
			globals

all-traces: basic.vgtrace \
						meng-thesis-example.vgtrace \
						array-overflow.vgtrace \
						array-param.vgtrace \
						struct-basic.vgtrace \
						globals.vgtrace


%: %.c
	gcc -ggdb -O0 -fno-omit-frame-pointer $< -o $@

%.vgtrace: % ../valgrind-3.11.0/inst/bin/valgrind
	# always return 'success' to keep 'make' running even on errors
	../valgrind-3.11.0/inst/bin/valgrind --tool=memcheck --source-filename=$<.c --trace-filename=$<.vgtrace ./$< || true
