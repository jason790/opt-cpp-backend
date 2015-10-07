all:  basic \
			meng-thesis-example \
			array-overflow \
			array-param \
			struct-basic \
			globals \
			string-array \
			structs-and-arrays \
			pointer-chain \
			typedef-test \
			type-qualifiers \
			shadowing

all-traces: basic.trace \
						meng-thesis-example.trace \
						array-overflow.trace \
						array-param.trace \
						struct-basic.trace \
						globals.trace \
						string-array.trace \
						structs-and-arrays.trace \
						pointer-chain.trace \
						typedef-test.trace \
						type-qualifiers.trace \
						shadowing.trace


%: %.c
	gcc -ggdb -O0 -fno-omit-frame-pointer $< -o $@

%.vgtrace: % ../valgrind-3.11.0/inst/bin/valgrind
	# always return 'success' to keep 'make' running even on errors
	../valgrind-3.11.0/inst/bin/valgrind --tool=memcheck --source-filename=$<.c --trace-filename=$<.vgtrace ./$< || true

%.trace: %.vgtrace ../vg_to_opt_trace.py
	python ../vg_to_opt_trace.py --create_jsvar=trace $(basename $<) > $(basename $<).trace || true
