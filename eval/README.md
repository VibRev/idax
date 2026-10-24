# idax 评测任务集

这是给 [axkit-eval](https://github.com/VibRev/axkit/tree/main/eval) 用的 idax 任务集。每个任务里，agent 只能用 idax 一个工具，回答一个关于 ARM64 fixture 的逆向问题。

- **判定**：真值要么是恢复出来的字符串，要么是保存到数据库里的改动，不依赖会随构建或引擎版本漂移的地址。
- **横向对比**：[bnx/eval](https://github.com/VibRev/bnx/tree/main/eval) 用的是同一批 fixture 和同一批问题。

**结论**：CLI、CLI + skill、`idax mcp` 都能完成几乎全部任务。`idax mcp` 在 claude 和 grok 上用的 token 最少，比官方 ida-mcp 少 40–50%；ida-headless-mcp 的 token 是它的 2–7 倍。详见 [评测报告](https://github.com/VibRev/axkit/blob/main/eval/reports/2026-10-24-slim.md)。

## 跑

```sh
cargo build                       # 先有 target/debug/idax
cd eval
axkit-eval check suite.toml       # 只加载校验
axkit-eval run suite.toml --group claude --task password --reps 1   # 单个组的单个任务
axkit-eval run suite.toml                                           # 全部组、全部任务
axkit-eval summary ../target/eval-data/results.jsonl
```

`suite.toml` 的 `setup` 会用 `aarch64-linux-gnu-gcc` 把 `fixtures/*.c` 编成 stripped 的 ARM64 小程序。

- 没有交叉编译器的机器（例如 macOS）会改从 `fixtures/bin/` 拷预编译产物。那里同时存着编译用的源码，源码改过就拒绝拷贝，并提示到有编译器的机器上运行 `make -C fixtures prebuilt`。
- 反编译类任务要求 license 包含 ARM 的 Hex-Rays。

## 任务（由易到难）

| id | 考点 | 真值 |
|---|---|---|
| `password` | 明文字符串常量 | `s3cret_42` |
| `xor-flag` | XOR 解码：反编译后心算，明文不在二进制里 | `FLAG{xor_ok}` |
| `add-cipher` | 常量加法解码 | `admin:hunter2` |
| `calls-system` | 交叉引用和调用图：找出唯一调用 `system()` 的函数 | 地址 + `system` |
| `rename-save` | 改名并 `save`，判定脚本重开数据库查符号 | 持久化的 `decrypt_me` |
| `spill-needle` | 约 60 个函数的大输出，靠翻页或 spill 文件找唯一的特征串 | `needle_7f3a_marker` |
| `long-function` | 一个反编译出来约 40 KB 的函数，见表下说明 | `LONG{spill_files_are_read_9b2e}` |

`long-function` 的设计：

- **输出必然被截断**：反编译结果约 40 KB，远超 agent 的 8 KB 输出窗口，答案只能从 spill 文件或过滤后的输出里拿到。
- **没有现成的字符串**：秘密串隔一个字节存一个，顺序打乱，夹在数百条无关的 volatile 更新之间，所以没有哪一行单独包含它，编译器和反编译器也没法把它合并成字符串常量。
- **还要读懂 main**：main 是隔一个字节打印一个的。
- **源码怎么来**：`longfunc.c` 由 `fixtures/gen_longfunc.py` 用固定种子生成，生成的 C 源码和预编译产物一起提交。

## 分组

| 组 | agent 拿到什么 |
|---|---|
| `claude` / `codex` / `grok` | PATH 上的 idax，没有 skill，只有 `idax --help` 和 `idax ref` |
| `*-skill` | 同上，并把 `idax skills` 的输出装成项目级 skill |
| `*-mcp` | `idax mcp`（stdio，code mode）；PATH 上没有 CLI，也不装 skill |
| `*-idamcp` | 官方 Hex-Rays ida-mcp，位置由环境变量 `AXEVAL_IDA_MCP` 给出 |
| `*-ihmcp` | ida-headless-mcp，位置由环境变量 `AXEVAL_IDA_HEADLESS_MCP` 给出 |
| `smoke-*` | 每个 harness 最便宜的模型，用来冒烟 |

- **claude 的权限**：claude 组以 `--permission-mode auto` 运行，不设允许列表，与 codex 的 `danger-full-access` 对等。
- **MCP 组的工具**：claude 和 grok 没有 shell，codex 的 shell 只读。
- **ida-mcp 的状态目录**：`IDA_MCP_STATE_DIR`、`IDA_NEXUS_STATE_DIR` 放在本次运行的私有 `{tmp}` 里，不写 `~/.idapro`。
- **运行之间的隔离**：每次运行有独立的 `IDAX_RUNTIME_DIR` 和 `XDG_CACHE_HOME`，随输出目录一起清理；`AXKIT_AGENT=on` 让 idax 使用有界输出的默认值。

```sh
AXEVAL_IDA_MCP=/path/to/venv/bin/ida-mcp AXEVAL_IDA_HEADLESS_MCP=/path/to/ida-headless-mcp \
  axkit-eval run suite.toml --group claude-idamcp --group claude-ihmcp
```

## 判定脚本

`fixtures/check_rename.sh` 在工作区里找保存出来的 `.i64` / `.idb`，不限于 target 旁边，被测工具存到哪里都行。

- 每个找到的数据库都用 idax 重新打开一遍，任意一个的函数名里出现 `decrypt_me` 就算通过。
- 它用本次运行的环境，所以调到的是 PATH 上的 idax 和本次运行的 daemon。
