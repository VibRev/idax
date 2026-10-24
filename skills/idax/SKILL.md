---
name: idax
description: Reverse engineer native binaries (ELF, PE, Mach-O, firmware blobs) with IDA Pro from the shell through the idax CLI - decompile and disassemble functions, list functions, strings and imports, follow cross references, rename, comment, retype and patch, then save the database. Use when analysing or changing a native binary with IDA, or answering "what does this function do", "who calls X", "where is this string used".
metadata:
  version: "0.2.0"
---

# idax

`idax exec <target> 'CODE'` runs IDAPython against the target and prints the answer. The
first command opens the target in a background daemon and waits for analysis; later commands
reuse the session. The target is any binary IDA loads, or an `.i64` / `.idb`.

The same sessions are also served over MCP: `idax mcp` is a stdio server with the tools
exec, ref, save, close and list. Configure it in the MCP client when shell access is not available.

## Rules

1. **Read before you change.** Look at the function, bytes or name you are about to change.
2. **Read back after you change.** Return the new state from the same script and check it.
3. **Close the sessions you opened** when you are done: `idax close <target>`.
4. **Nothing lasts without `idax save`.** `close`, a crash or an idle daemon drops unsaved changes.
5. **Write the code inside the exec quotes**, several lines if needed. Do not `cd`, do not
   write temporary script files.

## Workflow

```sh
idax exec fw.bin '[(hex(ea), ida_funcs.get_func_name(ea)) for ea in idautils.Functions()]'
idax exec fw.bin 'str(ida_hexrays.decompile(idc.get_name_ea_simple("main")))'
idax ref xrefs to
idax close fw.bin
```

The code is plain IDAPython: IDA's modules (`idaapi`, `idc`, `idautils`, `ida_funcs`, `ida_bytes`,
`ida_hexrays`, ...) are imported, nothing else is defined. The answer is the last expression's
value; `print()` lines come first.

**Unsure of an API? `idax ref <words>` before guessing.** It searches the IDA install's Python
modules and prints signatures with file:line.

## Questions

Each cell is the code for `idax exec fw.bin '...'`.

| question | code |
|---|---|
| biggest functions | `sorted(((ida_funcs.calc_func_size_ea(ea), ida_funcs.get_func_name(ea)) for ea in idautils.Functions()), reverse=True)[:20]` |
| what a function does | `str(ida_hexrays.decompile(idc.get_name_ea_simple("main")))` |
| its instructions | `[(hex(ea), idc.generate_disasm_line(ea, 0)) for ea in idautils.FuncItems(idc.get_name_ea_simple("check"))]` |
| who calls it | `sorted({ida_funcs.get_func_name(x.frm) for x in idautils.XrefsTo(idc.get_name_ea_simple("check"))})` |
| who calls an import | `sorted({ida_funcs.get_func_name(x.frm) for x in idautils.XrefsTo(idc.get_name_ea_simple(".puts"))})` |
| strings with a word | `[(hex(s.ea), str(s)) for s in idautils.Strings() if "access" in str(s)]` |
| where a string is used | `[hex(x.frm) for s in idautils.Strings() if str(s) == "access granted" for x in idautils.XrefsTo(s.ea)]` |
| its C prototype | `idc.get_type(idc.get_name_ea_simple("main"))` |

## Changing things

```sh
idax exec fw.bin 'ea = idc.get_name_ea_simple("main")
ida_name.set_name(ea, "entry_main")
ida_funcs.get_func_name(ea)'
idax save fw.bin
```

A binary saves as `fw.bin.i64` beside it, an `.i64` over itself, `--to PATH` elsewhere.

## Output

Under an agent the output is cut at about 8 KB; the last line then names a file with all of it:
`# records 1-40 of 1523 shown; full output saved to <file>`.

Errors print `Error: <kind>: <message>` with a `hint:` line: follow it. Exit 3 means the session
was lost (rerun). `idax --help` has the details; `idax ref` lists the topics and where IDA keeps
its API and official examples.
