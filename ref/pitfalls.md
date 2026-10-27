# pitfalls: IDAPython without a UI, under idax
## deprecated names
Since IDA 9.4, IDA deprecates the func_t-taking calls (ida_funcs.get_func, calc_func_size, get_func_ranges, ...) in favour of ones taking an address (get_func_start, calc_func_size_ea, get_func_ranges_ea); the old ones still work but print a DeprecationWarning on stderr naming the new one.
    idax exec fw.bin 'ea = idc.get_name_ea_simple("check"); hex(ida_funcs.get_func_start(ea + 4)), ida_funcs.calc_func_size_ea(ea)'
## rename a function or address
ida_name.set_name(ea, "new_name") names any address, a function's start included; it returns False when the name is taken or invalid. The example puts the old name back.
    idax exec fw.bin 'ea = idc.get_name_ea_simple("check"); ida_name.set_name(ea, "check_pw"), ida_funcs.get_func_name(ea), ida_name.set_name(ea, "check")'
## not found is BADADDR
Name and address lookups return idaapi.BADADDR (0xffffffffffffffff), not an exception, when nothing matches.
    idax exec fw.bin 'idc.get_name_ea_simple("mian") == idaapi.BADADDR'
## imports and their stubs
An import such as puts lives in extern; the code calls its PLT stub `.puts`, so the call sites are the references to the stub.
    idax exec fw.bin 'sorted({ida_funcs.get_func_name(x.frm) for x in idautils.XrefsTo(idc.get_name_ea_simple(".puts"))})'
## the decompiler is licensed per processor
ida_hexrays.decompile fails when the license has no Hex-Rays for the binary's processor; disassembly still works.
    idax exec fw.bin 'ida_hexrays.init_hexrays_plugin(), ida_ida.inf_get_procname()'
## no UI
ida_kernwin's dialogs, choosers and jumpto do nothing headless; return values instead of showing them.
## wait for analysis after you add code
Creating functions or changing types queues analysis; ida_auto.auto_wait() lets it finish before reading back.
    idax exec fw.bin 'ea = idc.get_name_ea_simple("check"); ida_funcs.del_func(ea), ida_funcs.add_func(ea), ida_auto.auto_wait(), ida_funcs.get_func_name(ea)'
