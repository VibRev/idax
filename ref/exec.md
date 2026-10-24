# exec: what a script sees
## the namespace
IDA's own modules are imported (idaapi, idc, idautils, ida_funcs, ida_name, ida_bytes, ida_hexrays, ida_xref, ida_segment, ida_nalt, ida_typeinf, ...); import any other as usual. Nothing else is defined, and every run starts with a clean namespace.
    idax exec fw.bin 'ida_ida.inf_get_procname(), ida_ida.inf_is_64bit(), ida_loader.get_file_type_name()'
## the result
The answer is the value of the last expression, after the lines print() wrote. A list of dicts prints as a table with a `# key | key` header, a list as one line per item.
    idax exec fw.bin 'print(ida_funcs.get_func_qty()); [{"addr": hex(ea), "name": ida_funcs.get_func_name(ea)} for ea in idautils.Functions()][:3]'
## what converts to JSON
dict, list, tuple, str, int, float, bool and None as they are; bytes as hex; iterators are drained; anything else as its str(). Integers stay integers: hex(ea) for an address.
    idax exec fw.bin 'ida_bytes.get_bytes(idc.get_name_ea_simple("main"), 8)'
## code, files and stdin
The code is the argument after the target: one shell argument, as many lines as it needs. `-c CODE` says the same, and several `-c` run as one script, a line each. `-f FILE` runs a file; `-` or `-f -` reads the code from stdin.
    idax exec fw.bin 'for ea in idautils.Functions():
        print(hex(ea), ida_funcs.get_func_name(ea))'
    idax exec fw.bin - <<'EOF'
    print(ida_funcs.get_func_qty())
    EOF
## errors
An exception exits 1 with `Error: script_error: <Type>: <message> (at <exec>:<line>)`; the traceback, cut to your code, is on stderr. A misspelt name, a module's included, gets `hint: did you mean: ...?`.
    idax exec fw.bin 'ida_funcs.get_fnc(0)'   # exit 1
## the API
`idax ref <words>` searches the IDA install's ida_*.py, idc.py and idautils.py and prints each match as its signature, file:line and the first line of its docstring. Look an API up there before guessing at it.
    idax ref xrefs to
