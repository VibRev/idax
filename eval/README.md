# idax 评测任务集

给 [axkit-eval](../../axkit/eval) 用的 idax 任务集。agent 只拿到一个工具 idax，被问一个关于 ARM64 fixture 的逆向问题。真值要么是恢复出的字符串，要么是落盘的数据库改动，所以判定不依赖随构建或引擎漂移的地址。同一批 fixture 和同一批问题也出现在 [bnx/eval](../../bnx/eval)，便于横向对比。

## 跑

```sh
cargo build                       # 先有 target/debug/idax
cd eval
axkit-eval check suite.toml       # 校验
axkit-eval run suite.toml --group noskill --task password --reps 1   # 单任务
axkit-eval run suite.toml                                            # 全跑
axkit-eval summary ../target/eval-data/results.jsonl
```

`suite.toml` 的 `setup` 会用 `aarch64-linux-gnu-gcc` 把 `fixtures/*.c` 编成 stripped 的 ARM64 小程序（需要该交叉编译器）。没有交叉编译器的主机（macOS）从 `fixtures/bin/` 拷预编译产物，那里存着编译用的源码，源码变了就拒绝并提示在有编译器的机器上 `make -C fixtures prebuilt`。fixture 全是 ARM64，反编译类任务需要 license 含 ARM 的 Hex-Rays。

## 任务（由易到难）

| id | 考点 | 真值 |
|---|---|---|
| `password` | 明文字符串常量 | `s3cret_42` |
| `xor-flag` | XOR 解码（反编译 + 心算，明文不在二进制里） | `FLAG{xor_ok}` |
| `add-cipher` | 常量加法解码 | `admin:hunter2` |
| `calls-system` | 交叉引用 / 调用图：找唯一调用 `system()` 的函数 | 地址 + `system` |
| `rename-save` | 改名并 `save`，判定脚本重开数据库查符号 | 持久化的 `decrypt_me` |
| `spill-needle` | ~60 个函数的大输出，翻页/spill 找唯一特征串 | `needle_7f3a_marker` |
| `long-function` | 一个反编译出来约 930 行（约 40 KB）的函数，远超 agent 的 8 KB 窗口：输出必然被截断，答案只在 spill 出来的全文里。秘密串的字节隔一个存一个、顺序打乱、夹在数百条无关的 volatile 更新之间，所以没有哪一行单独包含它，也无法被编译器或反编译器合并成字符串常量；还要看懂 main 按隔字节打印 | `LONG{spill_files_are_read_9b2e}` |

`longfunc.c` 由 `fixtures/gen_longfunc.py` 生成（固定种子，`python3 gen_longfunc.py > longfunc.c`），生成后的 C 源码与预编译产物一起提交。

## 分组

- `noskill`：只有 `idax --help` 和 `idax ref`。
- claude 组以 `--permission-mode auto` 运行，不设允许列表，与 codex 的 `danger-full-access` 对等。第一轮 bnx 的 4 次失败、第二轮 long-function 的 1 次失败都是被允许列表拦下的，不是工具本身的问题。
- `skill`：装上 `../skills/idax`（由 skill 侧提供），用来量 skill 带来的差异。

每个运行有独立的 `IDAX_RUNTIME_DIR` 和 `XDG_CACHE_HOME`，随输出目录一起清理；`AXKIT_AGENT=on` 让 idax 用有界输出默认值。

- CLI 对 MCP：`claude-idamcp` / `codex-idamcp` / `grok-idamcp` 换成官方 Hex-Rays ida-mcp，`*-ihmcp` 换成 ida-headless-mcp；server 位置由运行器环境的 `AXEVAL_IDA_MCP`、`AXEVAL_IDA_HEADLESS_MCP` 给出。ida-mcp 的状态目录（`IDA_MCP_STATE_DIR`、`IDA_NEXUS_STATE_DIR`）放进 `{tmp}`，不写 `~/.idapro`。

```sh
AXEVAL_IDA_MCP=/path/to/venv/bin/ida-mcp AXEVAL_IDA_HEADLESS_MCP=/path/to/ida-headless-mcp \
  axkit-eval run ../../idax/eval/suite.toml --group claude-idamcp --group claude-ihmcp
```

## 判定脚本

`fixtures/check_rename.sh` 在工作区里找保存出来的 `.i64` / `.idb`（被测工具放在哪都行，不限于 target 旁边），逐个用 idax 重开，任一个的函数名里出现 `decrypt_me` 即通过。它用本运行的环境，所以 idax 在 PATH 上、用本运行的 daemon。

- `idax` 自己的 MCP：`claude-mcp` / `codex-mcp` / `grok-mcp` 用 `idax mcp`（stdio，code mode：`exec`、`ref`、`save`、`close`、`list`）代替 CLI，其余设置与上面的 MCP 组相同：PATH 上没有 CLI，不装 skill，claude 和 grok 没有 shell，codex 的 shell 只读。
