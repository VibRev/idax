# idax

IDA Pro 9.4 for agents: a persistent headless session scripted in native IDAPython, as a CLI and a code-mode MCP server.

idax 是给 agent 用的 IDA Pro 命令行工具。二进制只在后台 daemon 里打开一次，之后的查询和修改都写成 Python 脚本，直接调用 IDA 原生的 IDAPython API。

命令、会话、daemon、输出这些通用部分来自 [rex](https://github.com/VibRev/rex)，约定见 [rex CONVENTIONS](https://github.com/VibRev/rex/blob/main/docs/CONVENTIONS.md) 和 [axkit CONVENTIONS](https://github.com/VibRev/axkit/blob/main/docs/CONVENTIONS.md)。本仓库只放 IDA 特有的部分：worker 里的 idalib 后端、Python prelude、`ref` 语料和帮助文本。

```sh
idax exec fw.bin 'ida_funcs.get_func_qty()'
idax exec fw.bin 'str(ida_hexrays.decompile(idc.get_name_ea_simple("main")))'
idax ref xrefs to
idax save fw.bin && idax close fw.bin
```

## 获取与构建

idax 通过 `path = "../rex"`、`path = "../axkit"` 依赖另外两个仓库，三个仓库要 clone 到同一个父目录下：

```sh
mkdir VibRev && cd VibRev
git clone https://github.com/VibRev/axkit
git clone https://github.com/VibRev/rex
git clone https://github.com/VibRev/idax
cd idax && IDADIR=/path/to/ida-pro-9.4 cargo build --release
```

- **只支持 IDA 9.4。** idalib 用的是 `blacktop/idalib` 的 `sdk-9.4.0` 分支，固定在 rev `a174a5c`。
- **IDA 安装目录**：`IDADIR` 指向它；不设时用 IDA 安装程序的默认位置 `~/ida-pro-9.4`。
  - build.rs 会把这个路径写进 rpath，运行时不用设 `LD_LIBRARY_PATH`。
  - 找不到安装时改为链接 SDK 自带的 stub。这样编出来的二进制命令行和单元测试都能用，但打不开数据库。
- **版本检查**：worker 启动时会检查实际加载的 IDA 版本，不是 9.4 就报 `engine_error`。
- **Python**：只用 IDA 自带的 IDAPython，不需要额外安装 Python 包。

## 平台

- **Linux**
- **macOS**（实测 macOS 15 / Apple Silicon）：`IDADIR` 指向 app 里放 dylib 的目录，即 `export IDADIR="/Applications/IDA Professional 9.4.app/Contents/MacOS"`，rpath 同样会写进二进制。

daemon 用 Unix socket，worker 依赖 fd 重定向。

## 命令

命令和全局 flag 与 bnx 完全相同，详见 [rex README](https://github.com/VibRev/rex/blob/main/README.md) 的「命令与全局 flag」一节。

| 命令 | 作用 |
|---|---|
| `open <target>` | 打开二进制或 `.i64` / `.idb`，等自动分析跑完 |
| `status [<target>]` / `list` | 会话状态，每个会话一行：`target \| analysis \| idle` |
| `exec <target> (CODE \| -c CODE... \| -f FILE \| -)` | 执行 Python。代码直接作为参数，多行也写在同一个参数里；会话不存在时自动打开 |
| `save <target> [--to PATH] [--force]` | 落盘并打印 `saved \| <path>`：二进制存为同目录下的 `<target>.i64`（例如 `fw.bin.i64`），数据库覆盖它自己 |
| `close <target>` | 关闭会话，不保存 |
| `ref [words...]` | 检索 IDA 安装里的 Python API 和 idax 自己的笔记；不需要会话，也不需要 license |
| `mcp` | 启动 stdio MCP server（见下） |
| `daemon serve\|status\|stop [--force]` | 管理 daemon |
| `skills [show [FILE] \| list]` | 打印 agent skill |

环境变量只有 `IDAX_MAX_BYTES` 和 `IDAX_TIMEOUT`。

## exec 里有什么

- **已导入的模块**：
  - `idaapi`、`idc`、`idautils`
  - `ida_auto`、`ida_bytes`、`ida_entry`、`ida_frame`、`ida_funcs`、`ida_gdl`、`ida_hexrays`、`ida_ida`
  - `ida_lines`、`ida_loader`、`ida_nalt`、`ida_name`、`ida_segment`、`ida_strlist`、`ida_typeinf`、`ida_ua`、`ida_xref`

  其他模块照常 `import`。除此之外没有定义任何 helper，每次 exec 都从干净的命名空间开始。
- **结果**是最后一个表达式的值：
  - dict、list、tuple、str、int、float、bool、None 原样输出；
  - bytes 转成十六进制，迭代器会展开；
  - 其他对象一律 `str()`。
- **异常**：traceback 只保留用户代码的帧。`AttributeError` / `NameError` 会给出近似的名字，对模块属性同样有效：`ida_funcs.get_fnc` 提示 `get_func`，裸写 `get_bytes` 提示 `ida_bytes.get_bytes`。
- **取消**：客户端断开（Ctrl-C）时，worker 给自己发 SIGINT，脚本里会抛出 `KeyboardInterrupt`，会话保留。`time.sleep` 这类阻塞调用也能打断。

## ref：在 IDA 安装里查 API

`ref` 语料只写 idax 自己的笔记，共三个主题：

- `exec`：命名空间、结果、错误；
- `session`：会话；
- `pitfalls`：IDA 9.4 的弃用、BADADDR、PLT stub、改名、headless 下的坑。

IDA 的 API 参考和官方示例不打包，而是在运行时实际加载的那份安装里现查。

**`idax ref <words>`**
- 逐行解析 `<IDADIR>/python` 下的 `ida_*.py`、`idc.py`、`idautils.py`，约 16000 个定义，一次约 40 ms，不缓存。
- 每条命中给出 `限定名(签名) -> 返回 | 绝对路径:行号 | docstring 首行`。SWIG 生成的 `(*args)` 签名，会换成 docstring 里写的真实签名。
- 名字精确命中或只有一处定义时，附上完整 docstring；结果最后附相关的官方示例。
- 查询是标识符（含 `_`、`.` 或大写字母）时，API 结果排在前面；普通词（如 `xrefs to`、`rename`）先给笔记。

```
$ idax ref get_func_name
ida_funcs.get_func_name(ea: ida_idaapi.ea_t) -> Union[str, None] | <IDADIR>/python/ida_funcs.py:858 | Get function name.
idc.get_func_name(ea) | <IDADIR>/python/idc.py:3249 | Retrieve function name
ida_funcs.func_t.get_name() | <IDADIR>/python/ida_funcs.py:554 | Get the function name
```

**`idax ref`（不带参数）**
- 先列出主题。
- 再列出安装里的两个位置和可以直接粘贴的 grep 命令：`<IDADIR>/python`（签名和 docstring）、`<IDADIR>/python/examples`（官方示例，`index.md` 是目录）。

**检索的局限**：这是按词面匹配，不认识同义词。比如 IDA 的改名接口是 `ida_name.set_name`，查 `rename` 排不出来，所以这类写法记在笔记里。

## MCP

`idax mcp` 是一个 stdio MCP server，采用 code mode，只有五个工具，各自对应同名命令：

- `exec {target, code, timeout?}`
- `ref {query}`
- `save {target, path?, force?}`
- `close {target}`
- `list {}`

工具定义合计约 2 KB。

**和 CLI 的关系**
- 共用同一个 daemon 和同一批会话：在 MCP 里打开的 target，命令行 `idax status` 也能看到。
- 输出上限和 agent 模式的 CLI 一样，约 8 KB；超出部分写进 spill 文件，最后一行给出它的路径。
- 报错格式同样是 `Error:` 加 `hint:`，工具结果会标上 `isError`。

```sh
claude mcp add idax -- idax mcp     # Claude Code
```

```json
{"mcpServers": {"idax": {"command": "idax", "args": ["mcp"]}}}
```

```toml
# ~/.codex/config.toml
[mcp_servers.idax]
command = "idax"
args = ["mcp"]
```

上面的 JSON 写在项目的 `.mcp.json` 里。

## skill

`skills/idax/SKILL.md` 是给 agent 用的 skill，编译时打包进二进制。idax 只负责把它打印出来，不负责安装：各家 harness 的 skill 目录不一样，而且经常变，由 agent 按自己所在的 harness 安装最可靠。

```sh
idax skills                 # 原样打印 SKILL.md，不截断
idax skills list            # skill 的全部文件
idax skills show SKILL.md   # 其中一个文件
```

frontmatter 里的 `metadata.version` 与 `idax --version` 相同，agent 拿已安装副本的版本跟它比，就知道是否过期了。

## 后端

- **每个会话一个 worker**：由 rex 管理的 `idax __worker` 子进程。原因是 idalib 一个进程只能打开一个库，而且必须在主线程上驱动。
- **数据库放在会话的私有工作目录里**：
  - 打开二进制时，IDA 用 `-o` 把数据库建在工作目录里；
  - 打开 `.i64` 时，rex 先把它复制进工作目录，再打开这份副本。
- **保存**：`save` 先用 `ida_loader.save_database` 写到目标旁边的临时文件，再由 rex rename 到最终位置。
- **打开时等分析**：总是等自动分析跑完才回答。idalib 的自动分析没有进度回调，等得久时由 daemon 打印进度行。

## 开发

```sh
cargo clippy --all-targets
cargo test          # 有 IDA 9.4 时，集成测试会真正跑 IDA
cargo fmt --check
```

**测试 fixture**：用的是 rex 的 `fixtures/fw.bin`，AArch64 ELF。
- 反编译相关的测试要求 license 包含 ARM 的 Hex-Rays 反编译器。
- 有 `aarch64-linux-gnu-gcc` 时现场编译。
- 没有时（例如 macOS）拷贝 `rex/fixtures/bin/` 里的预编译产物；源码对不上时跳过，并提示运行 `make -C rex/fixtures prebuilt`。

**示例测试**：`tests/cli.rs` 里的 `every_skill_example_runs` 和 `every_ref_example_runs`，会在 fixture 上逐条执行 SKILL.md 和 `ref` 语料里的示例。改了 skill 或语料之后要跑一遍。

**评测**：任务集在 [`eval/`](https://github.com/VibRev/idax/tree/main/eval)。CLI、skill、自带 MCP 与官方或第三方 MCP 的对比，见 [评测报告](https://github.com/VibRev/axkit/blob/main/eval/reports/2026-10-24-slim.md)。

## 待做

- 自动分析的百分比进度
- 兼容 ida-nexus 的实例发现协议，接管 GUI 里已经打开的库
- Windows

## 许可

Apache-2.0。
