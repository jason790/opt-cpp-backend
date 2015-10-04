# Convert a trace created by the Valgrind OPT C backend to a format that
# the OPT frontend can digest

# Created 2015-10-04 by Philip Guo

# pass in the $basename of a program. assumes that the trace is
# $basename.trace and the source file is $basename.c


import json
import pprint
import sys

pp = pprint.PrettyPrinter(indent=2)

RECORD_SEP = '=== pg_trace_inst ==='

def process_record(lines):
    if not lines:
        return
    rec = '\n'.join(lines)
    #print '---'
    #print rec
    try:
        obj = json.loads(rec)
        process_json_obj(obj)
    except ValueError:
        print >> sys.stderr, "Ugh, died!"
        sys.exit(1) # we dead!


def process_json_obj(obj):
    print '---'
    #pp.pprint(obj)
    #print

    assert len(obj['stack']) > 0 # C programs always have a main at least!
    obj['stack'].reverse() # make the stack grow down to follow convention


    # create an execution point object
    ret = {}

    heap = {}
    stack = []
    globals_obj = {}

    ret['ordered_globals'] = obj['ordered_globals']

    ret['line'] = obj['line']
    ret['func_name'] = obj['stack'][-1]['func_name'] # use the 'topmost' (last) entry

    # TODO: handle more event types
    ret['event'] = 'step_line'
    ret['stdout'] = '' # TODO: handle this

    ret['heap'] = heap
    ret['stack_to_render'] = stack
    ret['globals'] = globals_obj

    pp.pprint(ret)
    print

    return ret


if __name__ == '__main__':
    basename = sys.argv[1]
    cod = open(basename + '.c').read()
    cur_record_lines = []
    for line in open(basename + '.trace'):
        line = line.strip()
        if line == RECORD_SEP:
            process_record(cur_record_lines)
            cur_record_lines = []
        else:
            cur_record_lines.append(line)

    process_record(cur_record_lines) # process final record
