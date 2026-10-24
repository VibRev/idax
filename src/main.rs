//! `idax`: IDA Pro from the command line, for agents (README.md). The
//! commands, sessions and daemon are rex's; IDA itself is [`backend::Ida`].

mod backend;

use axkit::skills::SkillFile;
use rex::pyapi::Naming;
use rex::reference::{Docs, Place, Role};
use rex::save::Databases;
use rex::tool::Tool;
use std::process::ExitCode;

static IDAX: Tool = Tool {
    name: "idax",
    version: env!("CARGO_PKG_VERSION"),
    engine: "IDA",
    databases: Databases { extensions: &["i64", "idb"] },
    about: "IDA Pro for agents: open a binary once, then script it",
    examples: "\
Examples:
  idax exec ./fw.bin 'ida_funcs.get_func_qty()'      # opens the target on demand
  idax exec ./fw.bin 'for ea in idautils.Functions():
      print(hex(ea), ida_funcs.get_func_name(ea))'   # several lines in one argument
  idax exec ./fw.bin -f script.py                    # a file; - reads the code from stdin
  idax ref decompile                                 # search IDA's Python API, no session needed
  idax save ./fw.bin && idax close ./fw.bin          # nothing is written without save

The database stays open in a background daemon between commands. Nothing is
written next to the target until `idax save`.

Exit status: 0 ok, 1 error, 3 session lost or timeout.",
    exec_help: "\
The code is the argument after the target: one argument, as many lines as it
needs. -c CODE says the same (several -c run as one script), -f FILE runs a
file, and - (or -f -) reads the code from stdin.

The code is plain IDAPython: IDA's modules (idaapi, idc, idautils, ida_funcs,
ida_name, ida_bytes, ida_hexrays, ...) are imported, nothing else is defined.
The answer is the value of the last expression; lists of dicts print as a
table, strings as they are, other objects as their str().

Unsure of an API? `idax ref <words>` before guessing.

Examples:
  idax exec fw.bin 'ida_funcs.get_func_qty()'
  idax exec fw.bin 'str(ida_hexrays.decompile(idc.get_name_ea_simple(\"main\")))'
  idax exec fw.bin -f script.py",
    scripting: "IDAPython (IDA's modules imported, nothing else defined)",
    corpus: &[include_str!("../ref/exec.md"), include_str!("../ref/session.md"), include_str!("../ref/pitfalls.md")],
    docs: Docs {
        library: "libidalib",
        env: "IDADIR",
        naming: Naming::Stem,
        places: &[
            Place {
                role: Role::Api,
                paths: &["python"],
                holds: "API signatures and docstrings: ida_*.py, idautils.py, idc.py",
                tries: &["grep -n -A4 '^def get_func(' {}/ida_funcs.py", "grep -ln 'def decompile' {}/*.py"],
            },
            Place {
                role: Role::Examples,
                paths: &["python/examples"],
                holds: "official examples; index.md lists them",
                tries: &["grep -rln ctree_visitor_t {}", "grep -rl --include='*.py' XrefsTo {}"],
            },
        ],
    },
    skill: &[SkillFile { path: "SKILL.md", text: include_str!("../skills/idax/SKILL.md") }],
};

fn main() -> ExitCode {
    rex::tool::main::<backend::Ida>(&IDAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rex::reference::Corpus;

    #[test]
    fn every_ref_topic_parses_with_entries() {
        let corpus = Corpus::parse(IDAX.corpus);
        assert_eq!(corpus.topics().len(), IDAX.corpus.len(), "a text without a `# topic: about` line");
        for topic in corpus.topics() {
            assert!(!topic.about.is_empty() && !topic.entries.is_empty(), "{}", topic.name);
        }
    }

    #[test]
    fn the_command_line_is_consistent() {
        rex::cli::Cli::command_for(&IDAX).debug_assert();
    }
}
