//! idax against a real IDA 9.4: open, exec, status, save, close through the
//! daemon, as an agent would run them.
//!
//! Every test gets its own daemon (private runtime and cache directories).
//! Without a local IDA install they pass vacuously and say so; the
//! decompiler checks also need an AArch64 cross compiler, since the fixtures
//! are AArch64 (and the IDA license must include the ARM decompiler).

#![allow(clippy::unwrap_used)] // clippy.toml allows unwrap in #[test] fns only, not in these helpers

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

struct Env {
    dir: tempfile::TempDir,
}

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Env {
    /// `None` without an IDA install to run against.
    fn new() -> Option<Env> {
        let ida =
            std::env::var_os("IDADIR").map_or_else(|| PathBuf::from(std::env::var_os("HOME").unwrap()).join("ida-pro-9.4"), PathBuf::from);
        if !["libidalib.so", "libidalib.dylib"].iter().any(|lib| ida.join(lib).exists()) {
            eprintln!("skipped: no IDA 9.4 install at {}", ida.display());
            return None;
        }
        let dir = tempfile::tempdir().unwrap();
        for sub in ["run", "cache", "work"] {
            fs::create_dir(dir.path().join(sub)).unwrap();
            // The daemon refuses a runtime dir others can enter.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(dir.path().join(sub), fs::Permissions::from_mode(0o700)).unwrap();
            }
        }
        fs::copy(small_elf(), dir.path().join("work/true")).unwrap();
        Some(Env { dir })
    }

    fn work(&self) -> PathBuf {
        self.dir.path().join("work")
    }

    fn idax(&self, args: &[&str]) -> Out {
        self.idax_with(args, &[])
    }

    fn idax_with(&self, args: &[&str], env: &[(&str, &str)]) -> Out {
        let out = self.command(args, env).output().unwrap();
        Out {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8(out.stdout).unwrap(),
            stderr: String::from_utf8(out.stderr).unwrap(),
        }
    }

    fn command(&self, args: &[&str], env: &[(&str, &str)]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_idax"));
        cmd.args(args)
            .current_dir(self.work())
            .env_remove("CLAUDECODE")
            .env("IDAX_RUNTIME_DIR", self.dir.path().join("run"))
            .env("XDG_CACHE_HOME", self.dir.path().join("cache"));
        cmd.envs(env.iter().copied());
        cmd
    }

    /// `script` in `sh`, with the environment `command` gives idax.
    fn shell(&self, script: &str) -> Command {
        let mut cmd = Command::new("sh");
        cmd.arg("-c")
            .arg(script)
            .current_dir(self.work())
            .env_remove("CLAUDECODE")
            .env("IDAX_RUNTIME_DIR", self.dir.path().join("run"))
            .env("XDG_CACHE_HOME", self.dir.path().join("cache"));
        cmd
    }

    /// rex's shared fixture as `fw.bin`, built for AArch64 (decompiled
    /// with the ARM Hex-Rays); false without a cross compiler.
    fn fixture(&self) -> bool {
        aarch64_fixture("fw.c", "fw.bin", &self.work().join("fw.bin"))
    }

    /// An AArch64 binary with a `main` that calls `check`, or `None`
    /// without a cross compiler.
    fn arm_demo(&self) -> Option<PathBuf> {
        let bin = self.work().join("demo");
        aarch64_fixture("demo.c", "demo", &bin).then_some(bin)
    }
}

/// The binary the session tests call `true`: the host's `/usr/bin/true`
/// where that is an ELF (Linux), else rex's prebuilt AArch64 `fw.bin`. A
/// macOS `true` is a one-function Mach-O, too small to exercise truncation.
fn small_elf() -> PathBuf {
    let host = Path::new("/usr/bin/true");
    if fs::read(host).ok().is_some_and(|b| b.starts_with(b"\x7fELF")) {
        host.to_path_buf()
    } else {
        Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../rex/fixtures/bin/fw.bin")).to_path_buf()
    }
}

/// rex's AArch64 fixture `src` (`fw.c`, `demo.c`) built as `out`: by the
/// cross compiler where there is one, else copied from `rex/fixtures/bin`
/// (macOS hosts) as long as that copy was built from the same source.
fn aarch64_fixture(src: &str, prebuilt: &str, out: &Path) -> bool {
    let dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../rex/fixtures"));
    let built = Command::new("aarch64-linux-gnu-gcc").arg("-O1").arg("-o").arg(out).arg(dir.join(src)).status();
    if built.is_ok_and(|s| s.success()) {
        return true;
    }
    let fresh = fs::read(dir.join(src)).ok().is_some_and(|now| fs::read(dir.join("bin").join(src)).ok().as_ref() == Some(&now));
    if !fresh {
        eprintln!("no aarch64-linux-gnu-gcc, and rex/fixtures/bin/{src} is stale: run `make -C rex/fixtures prebuilt`");
        return false;
    }
    fs::copy(dir.join("bin").join(prebuilt), out).is_ok()
}

impl Drop for Env {
    fn drop(&mut self) {
        self.idax(&["daemon", "stop", "--force"]);
    }
}

#[test]
fn a_session_lives_across_commands_and_answers_in_bounded_records() {
    let Some(env) = Env::new() else { return };
    let open = env.idax(&["open", "true"]);
    assert_eq!(open.code, 0, "{}", open.stderr);
    assert!(open.stdout.starts_with("# target | analysis | idle\n"), "{}", open.stdout);
    assert!(open.stdout.contains(" | complete | "), "{}", open.stdout);

    let list = r#"[{"addr": hex(ea), "name": ida_funcs.get_func_name(ea)} for ea in idautils.Functions()]"#;
    let cut = env.idax_with(&["exec", "true", "-c", list, "--max-bytes", "200"], &[("AXKIT_AGENT", "on")]);
    assert_eq!(cut.code, 0, "{}", cut.stderr);
    assert!(!cut.stderr.contains("# progress: opening"), "open once, reuse after: {}", cut.stderr);
    let lines: Vec<&str> = cut.stdout.lines().collect();
    assert_eq!(lines[0], "# addr | name");
    let hint = lines.last().unwrap();
    assert!(hint.starts_with("# records 1-") && hint.contains(" shown; full output saved to ") && !hint.contains("--offset"), "{hint}");
    let spill = hint.split("full output saved to ").nth(1).unwrap();
    let full = env.idax(&["exec", "true", "-c", list]);
    assert_eq!(fs::read_to_string(spill).unwrap(), full.stdout, "the file holds what an unbounded run prints");

    let status = env.idax(&["status", "./true"]);
    assert!(status.stdout.contains(" | complete | "), "{}", status.stdout);

    assert_eq!(env.idax(&["close", "true"]).code, 0);
    assert_eq!(env.idax(&["list"]).stdout, "# no sessions\n");
}

#[test]
fn script_errors_and_usage_errors_exit_1_in_the_agreed_format() {
    let Some(env) = Env::new() else { return };
    let typo = env.idax(&["exec", "true", "-c", "print('before')\nida_funcs.get_fnc(0)"]);
    assert_eq!(typo.code, 1);
    assert_eq!(typo.stdout, "before\n", "prints made before the exception still show");
    assert!(
        typo.stderr.contains("Error: script_error: AttributeError: module 'ida_funcs' has no attribute 'get_fnc' (at <exec>:2)\n"),
        "{}",
        typo.stderr
    );
    assert!(typo.stderr.contains("hint: did you mean: get_func"), "a module's names are suggested too: {}", typo.stderr);
    let unbound = env.idax(&["exec", "true", "-c", "db"]);
    assert!(unbound.stderr.contains("NameError: name 'db' is not defined"), "idax binds no db: {}", unbound.stderr);
    env.idax(&["exec", "true", "-c", "x = 1"]);
    let clean = env.idax(&["exec", "true", "-c", "x"]);
    assert!(clean.stderr.contains("NameError: name 'x' is not defined"), "every run starts clean: {}", clean.stderr);

    let json = env.idax(&["exec", "true", "--json", "-c", "1/0"]);
    let last: serde_json::Value = serde_json::from_str(json.stderr.lines().last().unwrap()).unwrap();
    assert_eq!(last["error"]["kind"], "script_error");
    let out: serde_json::Value = serde_json::from_str(&json.stdout).unwrap();
    assert_eq!(out["analysis"]["complete"], true);

    let usage = env.idax(&["exec", "true", "--limt", "3"]);
    assert_eq!(usage.code, 1, "not clap's 2");
    assert!(usage.stderr.starts_with("Error: usage: "), "{}", usage.stderr);

    let missing = env.idax(&["exec", "nope", "-c", "1"]);
    assert_eq!(missing.code, 1);
    assert!(missing.stderr.starts_with("Error: not_found: "), "{}", missing.stderr);
}

#[test]
fn a_script_on_stdin_reaches_the_daemon() {
    let Some(env) = Env::new() else { return };
    for source in [&["-"][..], &["-f", "-"]] {
        let args: Vec<&str> = ["exec", "true"].into_iter().chain(source.iter().copied()).collect();
        let mut child = env.command(&args, &[]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(b"import sys\nprint(sys.argv)\nida_funcs.get_func_qty() > 0\n").unwrap();
        let out = child.wait_with_output().unwrap();
        assert_eq!(String::from_utf8(out.stdout).unwrap(), "['<stdin>']\ntrue\n", "{source:?}");
    }
}

#[test]
fn the_code_is_the_argument_and_a_file_takes_f() {
    let Some(env) = Env::new() else { return };
    let multi = env.idax(&["exec", "true", "n = 0\nfor ea in idautils.Functions():\n    n += 1\nn > 0"]);
    assert_eq!((multi.code, multi.stdout.as_str()), (0, "true\n"), "{}", multi.stderr);
    assert_eq!(env.idax(&["exec", "true", "-c", "a = 2", "-c", "a * 3"]).stdout, "6\n");
    fs::write(env.work().join("s.py"), "40 + 2\n").unwrap();
    assert_eq!(env.idax(&["exec", "true", "-f", "s.py"]).stdout, "42\n");
    let named = env.idax(&["exec", "true", "s.py"]);
    assert_eq!(named.code, 1);
    assert!(named.stderr.contains("Error: usage: CODE is Python, and s.py is a file\nhint: idax exec true -f s.py\n"), "{}", named.stderr);
    let empty = env.idax(&["exec", "true", "[ea for ea in idautils.Functions() if ea < 0]"]);
    assert_eq!(empty.code, 0, "{}", empty.stderr);
}

#[test]
fn a_client_that_goes_away_interrupts_its_script_and_keeps_the_session() {
    let Some(env) = Env::new() else { return };
    env.idax(&["open", "true"]);
    let mut client = env
        .command(&["exec", "true", "-c", "import time; time.sleep(60)"], &[])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_secs(2));
    client.kill().unwrap();
    client.wait().unwrap();
    let after = env.idax(&["exec", "true", "-c", "1 + 1"]);
    assert_eq!((after.code, after.stdout.as_str()), (0, "2\n"), "{}", after.stderr);
    assert!(!after.stderr.contains("# progress: opening"), "the session survived: {}", after.stderr);
}

#[test]
fn every_spelling_of_a_target_is_one_session() {
    let Some(env) = Env::new() else { return };
    #[cfg(unix)]
    std::os::unix::fs::symlink(env.work().join("true"), env.work().join("link")).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(env.work().join("true"), env.work().join("link")).unwrap();
    env.idax(&["exec", "true", "-c", "1"]);
    let again = env.idax(&["exec", "./link", "-c", "1"]);
    assert!(!again.stderr.contains("# progress: opening"), "{}", again.stderr);
    let abs = env.work().join("true");
    env.idax(&["exec", abs.to_str().unwrap(), "-c", "1"]);
    assert_eq!(env.idax(&["list"]).stdout.lines().count(), 2, "a header and one session");
}

#[test]
fn nothing_reaches_the_disk_without_save() {
    let Some(env) = Env::new() else { return };
    let rename = "ida_name.set_name(next(iter(idautils.Functions())), 'renamed_fn')";
    let database = env.work().join("true.i64");
    assert_eq!(env.idax(&["exec", "true", "-c", rename]).stdout, "true\n");
    env.idax(&["close", "true"]);
    assert!(!database.exists(), "close does not save");
    assert_eq!(fs::read_dir(env.work()).unwrap().count(), 1, "nothing beside the target");

    env.idax(&["exec", "true", "-c", rename]);
    let saved = env.idax(&["save", "true"]);
    assert_eq!(saved.code, 0, "{}", saved.stderr);
    assert_eq!(saved.stdout, format!("saved | {}\n", database.canonicalize().unwrap().display()));
    assert_eq!(fs::read_dir(env.work()).unwrap().count(), 2, "the database and nothing else beside the target");
    env.idax(&["close", "true"]);

    let reopened = env.idax(&["exec", "true.i64", "-c", "ida_funcs.get_func_name(next(iter(idautils.Functions())))"]);
    assert_eq!(reopened.stdout, "renamed_fn\n", "{}", reopened.stderr);
    let refused = env.idax(&["save", "true"]);
    assert_eq!(refused.code, 1, "no session of the binary is open");

    env.idax(&["exec", "true", "-c", "1"]);
    let hint = env.idax(&["open", "true"]);
    let foreign = env.idax(&["save", "true"]);
    assert_eq!(foreign.code, 1, "the database there was written by another session");
    assert!(foreign.stderr.contains("hint: idax save ") && foreign.stderr.contains(" --force"), "{}", foreign.stderr);
    assert!(!hint.stderr.contains("exists;"), "the hint is for opening afresh only: {}", hint.stderr);
}

#[test]
fn a_hung_script_times_out_and_loses_only_its_session() {
    let Some(env) = Env::new() else { return };
    let hung = env.idax(&["exec", "true", "--timeout", "2", "-c", "import time; time.sleep(30)"]);
    assert_eq!(hung.code, 3, "{}", hung.stderr);
    assert!(hung.stderr.lines().any(|l| l.starts_with("Error: timeout: ")), "{}", hung.stderr);
    assert_eq!(env.idax(&["list"]).stdout, "# no sessions\n");
    assert_eq!(env.idax(&["exec", "true", "-c", "2 + 2"]).stdout, "4\n", "a fresh session opens");
}

#[test]
fn the_decompiler_answers_with_c() {
    let Some(env) = Env::new() else { return };
    let Some(_demo) = env.arm_demo() else { return };
    let out = env.idax(&["exec", "demo", "-c", "ida_hexrays.decompile(idc.get_name_ea_simple('main'))"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stdout.contains("int __fastcall main("), "a cfunc that is not JSON prints as its str(): {}", out.stdout);
    assert!(out.stdout.contains("\"s3cret\""), "{}", out.stdout);

    let script = env.work().join("callers.py");
    fs::write(
        &script,
        "s = next(s for s in idautils.Strings() if 's3cret' in str(s))\nsorted({ida_funcs.get_func_name(x.frm) for x in idautils.XrefsTo(s.ea)})\n",
    )
    .unwrap();
    assert_eq!(env.idax(&["exec", "demo", "-f", "callers.py"]).stdout, "main\n");
}

/// `examples` from `markdown` run against the shared fixture as `fw.bin`
/// in `sh`, each ending with the exit status it says, none warning about a
/// deprecated API.
fn run_examples(env: &Env, markdown: &str, what: &str) -> usize {
    let bin_dir = Path::new(env!("CARGO_BIN_EXE_idax")).parent().unwrap().to_owned();
    let path = std::env::join_paths(std::iter::once(bin_dir).chain(std::env::split_paths(&std::env::var_os("PATH").unwrap()))).unwrap();
    let examples = rex::example::examples(markdown, "idax", "fw.bin");
    for example in &examples {
        let out = env.shell(&example.script).env("PATH", &path).output().unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        let context = format!("{what} line {}: {}\n{stderr}{}", example.line, example.script, String::from_utf8_lossy(&out.stdout));
        assert_eq!(out.status.code(), Some(i32::from(example.exit)), "{context}");
        assert!(!stderr.contains("DeprecationWarning"), "{context}");
    }
    examples.len()
}

#[test]
fn every_ref_example_runs() {
    let Some(env) = Env::new() else { return };
    if !env.fixture() {
        return;
    }
    let ran: usize = IDAX_CORPUS.iter().map(|(name, text)| run_examples(&env, text, name)).sum();
    assert!(ran > 12, "only {ran} examples");
}

#[test]
fn every_skill_example_runs() {
    let Some(env) = Env::new() else { return };
    if !env.fixture() {
        return;
    }
    let ran = run_examples(&env, include_str!("../skills/idax/SKILL.md"), "SKILL.md");
    assert!(ran > 10, "only {ran} examples");
    assert!(env.work().join("fw.bin.i64").exists(), "the skill's save example saved");
}

#[test]
fn ref_points_at_the_ida_install_and_its_greps_find_something() {
    let Some(env) = Env::new() else { return };
    let text = env.idax(&["ref"]);
    assert_eq!(text.code, 0, "{}", text.stderr);
    assert!(text.stdout.contains("# path | holds | try\n"), "{}", text.stdout);
    let install = text.stdout.lines().find_map(|l| l.strip_prefix("# the IDA API").and_then(|l| l.rsplit_once(": "))).unwrap().1;
    assert!(["libidalib.so", "libidalib.dylib"].iter().any(|lib| Path::new(install).join(lib).exists()), "{}", text.stdout);
    let tries: Vec<&str> =
        text.stdout.lines().skip_while(|l| *l != "# path | holds | try").skip(1).filter_map(|l| l.rsplit(" | ").next()).collect();
    assert!(tries.len() >= 2, "{}", text.stdout);
    for try_ in tries {
        let out = env.shell(try_).output().unwrap();
        assert!(out.status.success() && !out.stdout.is_empty(), "{try_}: {}", String::from_utf8_lossy(&out.stderr));
    }
}

#[test]
fn ref_words_search_the_installed_api_with_file_and_line() {
    let Some(env) = Env::new() else { return };
    let out = env.idax(&["ref", "xrefs", "to"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let line = out.stdout.lines().find(|l| l.starts_with("idautils.XrefsTo(ea, flags=0) | ")).unwrap_or_else(|| panic!("{}", out.stdout));
    let (file, at) = line.split(" | ").nth(1).unwrap().rsplit_once(':').unwrap();
    let source = fs::read_to_string(file).unwrap();
    let def = source.lines().nth(at.parse::<usize>().unwrap() - 1).unwrap();
    assert!(def.starts_with("def XrefsTo("), "{line} points at {def:?}");
    assert!(!out.stdout.contains("# ref exec: what converts to JSON"), "a note without the words stays out: {}", out.stdout);

    // An exact name shows its whole docstring.
    let exact = env.idax(&["ref", "get_func"]).stdout;
    assert!(exact.contains("ida_funcs.get_func(ea: ida_idaapi.ea_t) -> func_t * | "), "{exact}");
    assert!(exact.contains("\n    :param ea: any address in a function"), "{exact}");
    // The tool's own note on renaming comes before the engine's API.
    let rename = env.idax(&["ref", "rename"]).stdout;
    assert!(rename.starts_with("# ref pitfalls: rename a function or address\n"), "{rename}");
}

#[test]
fn mcp_serves_exec_and_ref_over_stdio() {
    let Some(env) = Env::new() else { return };
    let mut child = env.command(&["mcp"], &[]).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let lines = [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"exec","arguments":{"target":"true","code":"print('hi')\nida_funcs.get_func_qty() > 0"}}}"#,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"exec","arguments":{"target":"true","code":"nme"}}}"#,
        r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"ref","arguments":{"query":"get_func_name"}}}"#,
        r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"close","arguments":{"target":"true"}}}"#,
    ];
    child.stdin.take().unwrap().write_all((lines.join("\n") + "\n").as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let replies: Vec<serde_json::Value> =
        String::from_utf8(out.stdout).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(replies.len(), 6, "{replies:?}");
    assert_eq!(replies[0]["result"]["serverInfo"]["name"], "idax");
    assert!(replies[0]["result"]["instructions"].as_str().unwrap().contains("IDAPython"));
    let names: Vec<&str> = replies[1]["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["exec", "ref", "save", "close", "list"]);
    let text = |i: usize| replies[i]["result"]["content"][0]["text"].as_str().unwrap().to_owned();
    assert_eq!((text(2), &replies[2]["result"]["isError"]), ("hi\ntrue\n".to_owned(), &serde_json::json!(false)), "{:?}", replies[2]);
    assert_eq!(replies[3]["result"]["isError"], true);
    assert!(text(3).contains("Error: script_error: ") && text(3).contains("\nhint: "), "{}", text(3));
    assert!(
        text(4).starts_with("ida_funcs.get_func_name(ea: ida_idaapi.ea_t) -> Union[str, None] | "),
        "an identifier puts the API first: {}",
        text(4)
    );
    assert_eq!(replies[5]["result"]["isError"], false, "{}", text(5));
}

#[test]
fn skills_prints_the_bundled_skill_whole_even_to_an_agent() {
    let Some(env) = Env::new() else { return };
    let skill = include_str!("../skills/idax/SKILL.md");
    for args in [&["skills"][..], &["skills", "show"], &["skills", "show", "SKILL.md"]] {
        // A window far smaller than the skill: it must not apply.
        let out = env.idax_with(args, &[("CLAUDECODE", "1"), ("IDAX_MAX_BYTES", "200")]);
        assert_eq!(out.code, 0, "{}", out.stderr);
        assert_eq!(out.stdout, skill, "{args:?}");
    }
    assert_eq!(env.idax(&["skills", "list"]).stdout, format!("# path | bytes\nSKILL.md | {}\n", skill.len()));
    let version = format!("metadata:\n  version: \"{}\"\n", env!("CARGO_PKG_VERSION"));
    assert!(skill.contains(&version), "the skill's version is idax's, for an agent to compare");
    let help = env.idax(&["--help"]).stdout;
    assert!(help.contains("`idax skills` prints the agent skill (SKILL.md); install it where your harness loads skills."), "{help}");
}

const IDAX_CORPUS: &[(&str, &str)] = &[
    ("ref/exec.md", include_str!("../ref/exec.md")),
    ("ref/session.md", include_str!("../ref/session.md")),
    ("ref/pitfalls.md", include_str!("../ref/pitfalls.md")),
];
