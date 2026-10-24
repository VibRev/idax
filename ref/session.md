# session: sessions, analysis and saving
## sessions
The first command on a target opens it in a background daemon and waits for auto-analysis; later commands reuse it. `./fw.bin`, `/abs/fw.bin` and a symlink are one session.
    idax list
    idax status fw.bin
## saving
Nothing touches the disk until `save`, which prints where it wrote. A binary saves as `<name>.i64` beside it, a database over itself; `--to PATH` writes elsewhere. `close` never saves.
    idax save fw.bin
    idax save fw.bin --to fw-annotated.i64
## lost sessions
Exit 3 means the IDA worker crashed or timed out: the session and its unsaved changes are gone. Rerun to open a fresh one; `--timeout SECS` gives slow scripts longer (0: no limit). A client that goes away (Ctrl-C) interrupts its script with a KeyboardInterrupt; the session stays.
## as an MCP server
`idax mcp` is a stdio MCP server with five tools, exec, ref, save, close and list, each one the command of that name; configure the command `idax` with the argument `mcp` in the MCP client. Sessions, output and saving work as on the command line.
