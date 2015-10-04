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
    top_stack_entry = obj['stack'][-1]

    # create an execution point object
    ret = {}

    heap = {}
    stack = []
    enc_globals = {}
    ret['heap'] = heap
    ret['stack_to_render'] = stack
    ret['globals'] = enc_globals

    ret['ordered_globals'] = obj['ordered_globals']

    ret['line'] = obj['line']
    ret['func_name'] = top_stack_entry['func_name'] # use the 'topmost' entry's name

    # TODO: handle more event types
    ret['event'] = 'step_line'
    ret['stdout'] = '' # TODO: handle this

    for g_var, g_val in obj['globals'].iteritems():
        enc_globals[g_var] = encode_value(g_val, heap)

    for e in obj['stack']:
        stack_obj = {}
        stack.append(stack_obj)

        stack_obj['func_name'] = e['func_name']
        stack_obj['ordered_varnames'] = e['ordered_varnames']
        stack_obj['is_highlighted'] = e is top_stack_entry

        # hacky: does FP (the frame pointer) serve as a unique enough frame ID?
        # sometimes it's set to 0 :/
        stack_obj['frame_id'] = e['FP']

        stack_obj['unique_hash'] = stack_obj['func_name'] + '_' + stack_obj['frame_id']

        # unsupported
        stack_obj['is_parent'] = False
        stack_obj['is_zombie'] = False
        stack_obj['parent_frame_id_list'] = []

        enc_locals = {}
        stack_obj['encoded_locals'] = enc_locals

        for local_var, local_val in e['locals'].iteritems():
            enc_locals[local_var] = encode_value(local_val, heap)


    pp.pprint(ret)
    print

    return ret


# returns an encoded value in OPT format and possibly mutates the heap
def encode_value(obj, heap):
    if obj['kind'] == 'base':
        return ['C_DATA', obj['addr'], obj['type'], obj['val']]

    elif obj['kind'] == 'pointer':
        if 'deref_val' in obj:
            encode_value(obj['deref_val'], heap) # update the heap
        return ['C_PTR', obj['addr'], obj['val']]

    elif obj['kind'] == 'struct':
        ret = ['INSTANCE']
        ret.append(obj['type'])

        # sort struct members by address so that they look ORDERED
        members = obj['val'].items()
        members.sort(key=lambda e: e[1]['addr'])
        for k, v in members:
            entry = [k, encode_value(v, heap)] # TODO: is an infinite loop possible here?
            ret.append(entry)
        return ret

    elif obj['kind'] == 'array':
        ret = ['LIST']
        for e in obj['val']:
            ret.append(encode_value(e, heap)) # TODO: is an infinite loop possible here?
        return ret

    elif obj['kind'] == 'typedef':
        # pass on the typedef type name into obj['val'], then recurse
        obj['val']['type'] = obj['type']
        return encode_value(obj['val'], heap)

    elif obj['kind'] == 'heap_block':
        assert obj['addr'] not in heap
        new_elt = ['LIST']
        for e in obj['val']:
            new_elt.append(encode_value(e, heap)) # TODO: is an infinite loop possible here?
        heap[obj['addr']] = new_elt
        # TODO: what about heap-to-heap pointers?

    else:
        assert False


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
