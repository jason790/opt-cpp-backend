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
						shadowing.trace \
						pointers-gone-wild.trace \
						number-types.trace \
						cpp-first.trace


#%: %.c
#	@gcc -ggdb -O0 -fno-omit-frame-pointer $< -o $@

#%: %.cpp
#	@g++ -ggdb -O0 -fno-omit-frame-pointer $< -o $@

# use '|| true' to always return success and keep 'make' running even on errors
#%.vgtrace: % ../valgrind-3.11.0/inst/bin/valgrind
#	../valgrind-3.11.0/inst/bin/valgrind --tool=memcheck --source-filename=$<.c --trace-filename=$<.vgtrace ./$< || true


%.vgtrace: %.c ../valgrind-3.11.0/inst/bin/valgrind
	@gcc -ggdb -O0 -fno-omit-frame-pointer $< -o $(basename $@)
	@../valgrind-3.11.0/inst/bin/valgrind --tool=memcheck --source-filename=$< --trace-filename=$(basename $<).vgtrace ./$(basename $<) || true

%.vgtrace: %.cpp ../valgrind-3.11.0/inst/bin/valgrind
	@g++ -ggdb -O0 -fno-omit-frame-pointer $< -o $(basename $@)
	@../valgrind-3.11.0/inst/bin/valgrind --tool=memcheck --source-filename=$< --trace-filename=$(basename $<).vgtrace ./$(basename $<) || true

%.trace: %.vgtrace ../vg_to_opt_trace.py
	@python ../vg_to_opt_trace.py --create_jsvar=trace $(basename $<) > $(basename $<).trace || true

clean:
	rm -f *.trace *.vgtrace *.out
