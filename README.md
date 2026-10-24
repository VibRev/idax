# idax

IDA Pro 的 agent-first 命令行工具：二进制在后台 daemon 里只打开一次，之后所有查询和修改都用 Python 脚本完成，脚本直接用 IDA 原生的 IDAPython API。命令、会话、daemon、输出都来自 [rex](../rex)（约定见 [rex CONVENTIONS](../rex/docs/CONVENTIONS.md)，建立在 [axkit CONVENTIONS](../axkit/docs/CONVENTIONS.md) 之上）；本仓库只有 IDA 自己的部分：worker 里的 idalib 后端、Python prelude、`ref` 语料和帮助文本。

```sh
idax exec fw.bin 'ida_funcs.get_func_qty()'
idax exec fw.bin 'str(ida_hexrays.decompile(idc.get_name_ea_simple("main")))'
idax ref xrefs to
idax save fw.bin && idax close fw.bin
```

## 构建

- **只支持 IDA 9.4**（rex §0.1）。idalib 用 `blacktop/idalib` 的 `sdk-9.4.0` 分支，固定在 rev `a174a5c`，不提供多 SDK 的 feature。
- `IDADIR` 指向 IDA 安装目录，未设时用 IDA 安装程序的默认位置 `~/ida-pro-9.4`。build.rs 会把这个路径写进 rpath，运行时不需要设置 `LD_LIBRARY_PATH`。找不到安装时改为链接 SDK 自带的 stub：这样编出来的二进制命令行和单元测试都能用，但打不开数据库。
- worker 启动时检查运行时加载的 IDA 版本，与 9.4 不符就报 `engine_error`（rex R-07）。
- 不需要额外的 Python 包，只用 IDA 自带的 IDAPython。
- 只支持 Linux / macOS：daemon 用 Unix socket，worker 依赖 fd 重定向。
- macOS（实测 macOS 15 / Apple Silicon）：`IDADIR` 指向 app 里放 dylib 的目录，即 `export IDADIR="/Applications/IDA Professional 9.4.app/Contents/MacOS"`；rpath 同样写进二进制。
- 测试 fixture 是 AArch64 ELF（`rex/fixtures`）：有 `aarch64-linux-gnu-gcc` 时现编，没有时（macOS）拷 `rex/fixtures/bin/` 里的预编译产物；那里同时存着编译用的源码，与当前源码不一致就跳过并提示 `make -C rex/fixtures prebuilt`。

```sh
cargo clippy --all-targets
cargo test          # 有 IDA 9.4 时集成测试真正跑 IDA；有 aarch64-linux-gnu-gcc 时再测反编译和 ref 的每条示例
cargo fmt --check
```

fixture 统一为 ARM64（license 需含 ARM 的 Hex-Rays 反编译器），反编译相关的测试用 `aarch64-linux-gnu-gcc` 现场编一个 ARM64 小程序。

## 命令

命令与全局 flag 两个工具完全相同，见 rex README。简表：

| 命令 | 作用 |
|---|---|
| `open <target>` | 打开二进制或 `.i64`/`.idb`，等自动分析跑完 |
| `status [<target>]` / `list` | 会话状态 |
| `exec <target> (CODE \| -c CODE... \| -f FILE \| -)` | 执行 Python：代码就是参数，多行写在一个参数里；会话不存在时自动打开 |
| `save <target> [--to PATH] [--force]` | 落盘：二进制存为旁边的 `<target>.i64`（`fw.bin.i64`），数据库覆盖自己；打印 `saved \| <path>` |
| `close <target>` | 关闭会话，不保存 |
| `ref [words...]` | 检索 IDA 安装里的 Python API 与 idax 自己的说明；无参数时列主题与安装里的位置。不需要会话和 license |
| `mcp` | stdio MCP server（见下） |
| `daemon serve\|status\|stop [--force]` | 管理 daemon |
| `skills [show [FILE] \| list]` | 打印 agent skill（见下） |

环境变量只有 `IDAX_MAX_BYTES` 与 `IDAX_TIMEOUT`。会话行是 `# target | analysis | idle`。

## skill

`skills/idax/SKILL.md` 是给 agent 的 skill，打包进二进制。idax 只负责把它交出来，不安装：各家 harness 的 skill 目录不同，而且一直在变，由 agent 按自己所在的 harness 装最可靠。

```sh
idax skills                 # 原样打印 SKILL.md，不截断（agent 模式下也是）
idax skills list            # skill 的全部文件
idax skills show SKILL.md   # 其中一个文件
```

frontmatter 的 `metadata.version` 与 `idax --version` 相同，agent 拿已装副本的版本和它比就知道是否过期。`tests/cli.rs` 的 `every_skill_example_runs` 和 `every_ref_example_runs` 把 SKILL.md 与 `ref` 语料里每条示例在共用 fixture（`rex/fixtures/fw.c` 编出的 `fw.bin`）上逐条执行并检查退出码；改 skill 或语料后跑它们。

## ref 与引擎自己的文档

`ref` 语料只放 idax 自己的东西：`exec`（命名空间、结果、错误）、`session`、`pitfalls`（IDA 9.4 的弃用、BADADDR、PLT stub、改名、headless 下的坑）。IDA 的 API 参考和官方示例不打包，而是在运行时实际加载的那份 IDA 安装里现查：

- `idax ref <words>` 逐行解析 `<IDADIR>/python` 下的 `ida_*.py`、`idc.py`、`idautils.py`（约 16000 个定义，一次 40 ms 左右，不缓存），每条命中给出 `限定名(签名) -> 返回 | 绝对路径:行号 | docstring 首行`；SWIG 生成的 `(*args)` 签名换成 docstring 里的真实签名。名字唯一或精确命中时附完整 docstring，最后附相关的官方示例（按 `summary:` / `keywords:` 和调用次数排）。查询是标识符（含 `_`、`.` 或大写）时 API 排在前面，普通词（`xrefs to`、`rename`）先给语料里的笔记：

  ```
  $ idax ref get_func_name
  ida_funcs.get_func_name(ea: ida_idaapi.ea_t) -> Union[str, None] | <IDADIR>/python/ida_funcs.py:858 | Get function name.
  idc.get_func_name(ea) | <IDADIR>/python/idc.py:3249 | Retrieve function name
  ida_funcs.func_t.get_name() | <IDADIR>/python/ida_funcs.py:554 | Get the function name
  ```
- 不带参数的 `idax ref` 在主题列表后列出安装里的位置，附可直接粘贴的 grep：`<IDADIR>/python`（签名与 docstring）、`<IDADIR>/python/examples`（官方示例，`index.md` 是目录）。找不到安装时一行 `hint:` 说明原因与 `IDADIR`。
- 词面检索不懂同义词：IDA 的改名是 `ida_name.set_name`，查 `rename` 排不出来，这类写法放在语料的笔记里。

## exec 里有什么

- **原生模块已导入**：`idaapi`、`idc`、`idautils`、`ida_auto`、`ida_bytes`、`ida_entry`、`ida_frame`、`ida_funcs`、`ida_gdl`、`ida_hexrays`、`ida_ida`、`ida_lines`、`ida_loader`、`ida_nalt`、`ida_name`、`ida_segment`、`ida_strlist`、`ida_typeinf`、`ida_ua`、`ida_xref`；其他模块照常 `import`。除此之外不定义任何东西，没有 helper，也没有 `db`。每次 exec 都从干净的命名空间开始。
- 结果：最后一个表达式的值。dict/list/tuple/str/int/float/bool/None 原样，bytes 转十六进制，迭代器展开，其他对象一律 `str()`。
- 异常：traceback 只保留用户代码帧；`AttributeError` / `NameError` 给出近似名，对模块同样有效（`ida_funcs.get_fnc` → `get_func`，裸 `get_bytes` → `ida_bytes.get_bytes`）。
- 取消：客户端断开（Ctrl-C）时 worker 向自己发 SIGINT，prelude 装了 Python 的 `default_int_handler`，脚本里抛出 `KeyboardInterrupt`，会话保留；`time.sleep` 这类阻塞调用也能打断。

## MCP

`idax mcp` 是 stdio MCP server，code mode，只有五个工具：`exec {target, code, timeout?}`、`ref {query}`、`save {target, path?, force?}`、`close {target}`、`list {}`，每个都是同名命令。它和 CLI 共用同一个 daemon 和会话：MCP 里打开的 target，命令行 `idax status` 也看得到。输出与 agent 模式的 CLI 一样有界（约 8 KB，超出写进 spill 文件，最后一行给出路径），报错同样是 `Error:` 加 `hint:`，工具结果标 `isError`。工具定义合计约 2 KB。

```sh
claude mcp add idax -- idax mcp                  # Claude Code；或项目里的 .mcp.json：
                                                # {"mcpServers": {"idax": {"command": "idax", "args": ["mcp"]}}}
```

```toml
# ~/.codex/config.toml
[mcp_servers.idax]
command = "idax"
args = ["mcp"]
```

## 后端

- 每个会话一个 `idax __worker` 子进程（rex 管理），因为 idalib 每个进程只能开一个库，而且必须在主线程上驱动。
- 打开二进制时 IDA 用 `-o` 把数据库建在会话的私有工作目录里；打开 `.i64` 时由 rex 先复制进工作目录再打开副本。`save` 用 `ida_loader.save_database(partial, 0)` 写到目标旁边的临时文件，再由 rex rename 到位。
- 打开时总是等自动分析跑完再回答。idalib 的自动分析没有进度回调，等待较久时由 daemon 报进度行。

## 评测

CLI、skill、自带 MCP 与官方或第三方 MCP 在同一任务集上的对比见 [评测报告](../axkit/eval/reports/2026-10-24-slim.md)；任务集在 [`eval/`](eval)。

## 待做

- 自动分析的百分比进度
- 兼容 ida-nexus 的实例发现协议，接管 GUI 里已打开的库
- Windows

## 许可

Apache-2.0。
