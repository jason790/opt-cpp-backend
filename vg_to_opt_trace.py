# Convert a trace created by the Valgrind OPT C backend to a format that
# the OPT frontend can digest

# Created 2015-10-04 by Philip Guo

import json
import sys

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
    #print obj
    pass


if __name__ == '__main__':
    cur_record_lines = []
    for line in open(sys.argv[1]):
        line = line.strip()
        if line == RECORD_SEP:
            process_record(cur_record_lines)
            cur_record_lines = []
        else:
            cur_record_lines.append(line)

    process_record(cur_record_lines) # process final record
