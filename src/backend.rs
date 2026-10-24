//! IDA as a rex [`Backend`]: one database in idalib, in the worker process.
//!
//! idalib holds one database per process and must be driven from the main
//! thread, which is why rex gives every session a worker of its own.
//! Scripts run through `prelude.py` in IDAPython; requests and answers go
//! through files in the session's directory.

use idalib::{IDB, IDBOpenOptions};
use rex::analysis::Analysis;
use rex::exec::ScriptRun;
use rex::proto::{ExecRequest, Launch, State, WorkerFailure};
use rex::worker::{Backend, Channel};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};

/// The engine idax is built for (rex §0.1).
pub const IDA_VERSION: (i32, i32) = (9, 4);

const PRELUDE: &str = include_str!("prelude.py");

pub struct Ida {
    idb: IDB,
    workdir: PathBuf,
    next: u64,
}

impl Backend for Ida {
    fn open(launch: &Launch, _channel: &Channel) -> Result<Ida, WorkerFailure> {
        let version = idalib::version().map_err(|e| WorkerFailure::engine(format!("cannot read the IDA version: {e}")))?;
        if (version.major(), version.minor()) != IDA_VERSION {
            let (major, minor) = IDA_VERSION;
            return Err(WorkerFailure::engine(format!(
                "idax is built for IDA {major}.{minor}, but IDA {}.{} was loaded",
                version.major(),
                version.minor()
            ))
            .with_hint(format!("point IDADIR at an IDA {major}.{minor} install and rebuild idax")));
        }
        idalib::init_library().map_err(|e| WorkerFailure::engine(format!("cannot initialise idalib: {e}")))?;
        let mut options = IDBOpenOptions::new();
        options.auto_analyse(true);
        // A binary is analysed into a database in the session's directory;
        // a database target arrives as the session's copy already.
        let idb_path = launch.workdir.join(format!("{}.i64", file_name(&launch.input)));
        if launch.input == launch.target {
            options.idb(&idb_path);
        }
        let idb =
            options.open(&launch.input).map_err(|e| WorkerFailure::target(format!("IDA cannot open {}: {e}", launch.target.display())))?;
        let ida = Ida { idb, workdir: launch.workdir.clone(), next: 0 };
        let prelude = ida.workdir.join("prelude.py");
        fs::write(&prelude, PRELUDE).map_err(|e| WorkerFailure::engine(format!("cannot write {}: {e}", prelude.display())))?;
        let load = format!(
            "import importlib.util, sys\n\
             spec = importlib.util.spec_from_file_location('idax_prelude', {path})\n\
             m = importlib.util.module_from_spec(spec)\n\
             sys.modules['idax_prelude'] = m\n\
             spec.loader.exec_module(m)\n\
             m.setup()\n",
            path = py_str(&prelude)
        );
        ida.python(&load).map_err(WorkerFailure::engine)?;
        Ok(ida)
    }

    /// A state that cannot be read counts as incomplete analysis: the
    /// answer then says so rather than pass for whole.
    fn state(&self) -> State {
        let read = self.call("m.state").unwrap_or(Value::Null);
        let complete = read["complete"].as_bool().unwrap_or(false);
        State {
            analysis: if complete { Analysis::COMPLETE } else { Analysis::INCOMPLETE },
            phase: (!complete).then(|| "auto-analysis".to_owned()),
        }
    }

    /// idalib's auto-analysis takes no progress callback and cannot be
    /// interrupted; the daemon says it is still waiting.
    fn analyze(&mut self, _channel: &Channel) {
        self.idb.auto_wait();
    }

    fn exec(&mut self, exec: &ExecRequest, channel: &Channel) -> Result<ScriptRun, WorkerFailure> {
        self.next += 1;
        let request = self.workdir.join(format!("req-{}.json", self.next));
        let answer = self.workdir.join(format!("ans-{}.json", self.next));
        let body = json!({ "code": exec.code, "filename": exec.filename, "answer": answer });
        fs::write(&request, body.to_string()).map_err(|e| WorkerFailure::engine(format!("cannot write {}: {e}", request.display())))?;
        // A cancel raises SIGINT, which the prelude made a KeyboardInterrupt
        // in the script.
        let ran =
            channel.interruptible(interrupt, || self.python(&format!("import idax_prelude\nidax_prelude.run({})\n", py_str(&request))));
        let _ = self.python("import idax_prelude\nidax_prelude.drain_interrupt()\n");
        let _ = fs::remove_file(&request);
        let stray = ran.map_err(WorkerFailure::engine)?;
        let text = fs::read_to_string(&answer).map_err(|e| WorkerFailure::engine(format!("the prelude wrote no answer: {e}")))?;
        let _ = fs::remove_file(&answer);
        let run: ScriptRun =
            serde_json::from_str(&text).map_err(|e| WorkerFailure::engine(format!("the prelude answered something unreadable: {e}")))?;
        Ok(ScriptRun { stderr: stray + &run.stderr, ..run })
    }

    fn save(&mut self, to: &Path) -> Result<(), WorkerFailure> {
        self.call(&format!("m.save, {}", py_str(to))).map(drop).map_err(WorkerFailure::engine)
    }
}

impl Ida {
    /// `idax_prelude.call(result, <fn_and_args>)`: the function's value.
    fn call(&self, fn_and_args: &str) -> Result<Value, String> {
        let result = self.workdir.join("call.json");
        self.python(&format!("import idax_prelude as m\nm.call({}, {fn_and_args})\n", py_str(&result)))?;
        let text = fs::read_to_string(&result).map_err(|e| format!("cannot read {}: {e}", result.display()))?;
        let mut out: Value = serde_json::from_str(&text).map_err(|e| format!("bad prelude output in {}: {e}", result.display()))?;
        match out.get("error").and_then(Value::as_str) {
            Some(e) => Err(e.to_owned()),
            None => Ok(out["value"].take()),
        }
    }

    /// Run a snippet of ours; what it printed outside the prelude's own
    /// capture comes back as text.
    fn python(&self, code: &str) -> Result<String, String> {
        let out = self.idb.run_python(code).map_err(|e| format!("IDAPython: {e}"))?;
        match out.error {
            Some(e) if !out.success => Err(format!("idax prelude failed: {e}\n{}", out.stderr)),
            _ => Ok(out.stdout + &out.stderr),
        }
    }
}

/// Raise SIGINT in this process: Python's handler turns it into a
/// `KeyboardInterrupt` in the running script.
#[cfg(unix)]
fn interrupt() {
    // SAFETY: kill only sends a signal; the prelude installed the handler.
    unsafe {
        libc::kill(libc::getpid(), libc::SIGINT);
    }
}

/// Windows has no SIGINT to send a process: ask the Python runtime IDA
/// loaded to act as if one arrived (`PyErr_SetInterrupt`, safe from any
/// thread), which the prelude's handler turns into a `KeyboardInterrupt`.
#[cfg(windows)]
fn interrupt() {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

    let wide = |s: &str| s.encode_utf16().chain([0]).collect::<Vec<u16>>();
    // The versioned DLL holds the runtime; `python3.dll` only forwards to it.
    let names = (8..=20).rev().map(|minor| format!("python3{minor}.dll")).chain(["python3.dll".to_owned()]);
    for name in names {
        // SAFETY: a NUL-terminated name; a module is only looked up, not loaded.
        let module = unsafe { GetModuleHandleW(wide(&name).as_ptr()) };
        if module.is_null() {
            continue;
        }
        // SAFETY: a NUL-terminated symbol name, looked up in a loaded module.
        if let Some(set_interrupt) = unsafe { GetProcAddress(module, c"PyErr_SetInterrupt".as_ptr().cast()) } {
            // SAFETY: `void PyErr_SetInterrupt(void)` in every Python 3.
            let set_interrupt: unsafe extern "C" fn() = unsafe { std::mem::transmute(set_interrupt) };
            // SAFETY: documented as callable without the GIL, from any thread.
            unsafe { set_interrupt() };
            return;
        }
    }
}

fn file_name(path: &Path) -> String {
    path.file_name().map_or_else(|| "target".to_owned(), |n| n.to_string_lossy().into_owned())
}

/// A path as a Python string literal. JSON's escapes are a subset of
/// Python's, and serde never writes `\/`.
fn py_str(path: &Path) -> String {
    Value::String(path.to_string_lossy().into_owned()).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_become_python_literals() {
        assert_eq!(py_str(Path::new("/a/b \"c\".json")), r#""/a/b \"c\".json""#);
    }
}
