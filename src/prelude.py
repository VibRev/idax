"""idax's side of `exec`, loaded once into each worker's IDAPython.

A script sees IDA's native modules already imported (idaapi, idc,
idautils, ida_funcs, ...) and nothing else; each run starts clean.

The worker writes a request file and calls `run(request, answer)`; the
answer file gets one JSON object that rex renders: the script's stdout and
stderr, its result as JSON, and the exception it ended with. The answer is
written to a temporary name and renamed, so a whole file means a whole answer.
"""

import ast
import builtins
import collections.abc
import contextlib
import difflib
import importlib
import io
import json
import linecache
import os
import signal
import sys
import traceback

# Imported into every script's namespace, those IDA 9.4 has.
_MODULES = (
    "idaapi", "idc", "idautils", "ida_auto", "ida_bytes", "ida_entry", "ida_frame", "ida_funcs", "ida_gdl",
    "ida_hexrays", "ida_ida", "ida_lines", "ida_loader", "ida_nalt", "ida_name", "ida_segment", "ida_strlist",
    "ida_typeinf", "ida_ua", "ida_xref",
)

_modules = {}


def setup():
    """Import the native modules, and let SIGINT interrupt a script: the worker
    raises it when the script's client goes away."""
    for name in _MODULES:
        try:
            _modules[name] = importlib.import_module(name)
        except ImportError:
            pass
    signal.signal(signal.SIGINT, signal.default_int_handler)


def state():
    import ida_auto

    return {"complete": bool(ida_auto.auto_is_ok())}


def save(path):
    import ida_loader

    # Flags 0: write a packed copy and keep the session's unpacked files.
    if not ida_loader.save_database(path, 0):
        raise RuntimeError(f"IDA could not save the database to {path}")


def drain_interrupt():
    """Take a SIGINT that arrived after the script had finished, so that it
    does not land in the next request."""
    try:
        # The loop does nothing on purpose: Python delivers a pending signal at
        # the next bytecode boundary, so running a few raises it here.
        for _ in range(2):
            pass
    except KeyboardInterrupt:
        pass


def call(result_path, fn, *args):
    """Run one of the functions above for the worker: `{"value": ...}` or
    `{"error": "..."}` in the result file."""
    try:
        out = {"value": fn(*args)}
    except BaseException as e:  # noqa: BLE001 -- handed to the worker as is
        out = {"error": f"{type(e).__name__}: {e}"}
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(out, f)




def run(request_path):
    with open(request_path, encoding="utf-8") as fh:
        req = json.load(fh)
    filename = req["filename"]
    ns = {"__name__": "__main__", "__builtins__": builtins, **_modules}
    out, err = io.StringIO(), io.StringIO()
    answer = {"stdout": "", "stderr": "", "result": None, "error": None}
    notes = []
    saved = sys.argv, sys.stdin
    sys.argv, sys.stdin = [filename], io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                # So tracebacks can quote the user's lines.
                linecache.cache[filename] = (len(req["code"]), None, req["code"].splitlines(True), filename)
                tree = ast.parse(req["code"], filename=filename)
                last = None
                if tree.body and isinstance(tree.body[-1], ast.Expr):
                    last = ast.Expression(tree.body.pop().value)
                exec(compile(tree, filename, "exec"), ns)  # noqa: S102 -- what exec is for
                value = eval(compile(last, filename, "eval"), ns) if last is not None else None  # noqa: S307
                answer["result"] = _to_json(value, notes)
            except BaseException as e:  # noqa: BLE001 -- every failure is the script's answer
                answer["error"] = _failure(e, ns, filename)
    finally:
        sys.argv, sys.stdin = saved
    if answer["error"] is not None and answer["error"]["traceback"]:
        err.write("Traceback (most recent call last, user code only):\n" + answer["error"]["traceback"])
    for note in dict.fromkeys(notes):
        err.write(f"idax: result: {note}\n")
    answer["stdout"], answer["stderr"] = out.getvalue(), err.getvalue()
    if answer["error"] is not None:
        del answer["error"]["traceback"]
    tmp = req["answer"] + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(answer, fh)
    os.replace(tmp, req["answer"])


def _failure(e, ns, filename):
    user = [fr for fr in traceback.extract_tb(e.__traceback__) if fr.filename == filename]
    location = f"{filename}:{user[-1].lineno}" if user else None
    if isinstance(e, SyntaxError) and e.filename == filename:
        location = f"{filename}:{e.lineno}"
    return {
        "kind": type(e).__name__,
        "message": (e.msg or str(e)) if isinstance(e, SyntaxError) else str(e),
        "location": location,
        "suggestions": _suggestions(e, ns),
        "hint": None,
        "traceback": "".join(traceback.format_list(user)),
    }


def _suggestions(e, ns):
    name = getattr(e, "name", None)
    if not isinstance(name, str):
        return []
    if isinstance(e, AttributeError):
        obj = getattr(e, "obj", None)
        pool = [n for n in dir(obj) if not n.startswith("__")] if obj is not None else []
    elif isinstance(e, NameError):
        # A bare name is often one of a module's: get_bytes is ida_bytes.get_bytes.
        # The ida_* module first: idaapi and idc re-export much of it.
        modules = sorted(_modules.items(), key=lambda m: m[0] in ("idaapi", "idc"))
        exact = [f"{m}.{name}" for m, mod in modules if hasattr(mod, name)]
        attrs = {f"{m}.{a}": a for m, mod in modules for a in dir(mod) if not a.startswith("_")}
        close = set(difflib.get_close_matches(name, attrs.values(), n=3, cutoff=0.8))
        near = [q for q, a in attrs.items() if a in close and q not in exact]
        local = difflib.get_close_matches(name, [*ns, *dir(builtins)], n=3, cutoff=0.6)
        return [*exact, *local, *near][:5]
    else:
        return []
    return difflib.get_close_matches(name, pool, n=3, cutoff=0.6)


_MAX_ITEMS = 100_000


def _to_json(value, notes, depth=0):
    """`value` as JSON-ready data: containers element by element, iterators
    drained, bytes as hex, anything else as its str()."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if depth > 32:
        return str(value)
    if isinstance(value, dict):
        return {str(k): _to_json(v, notes, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset, collections.abc.Iterator)):
        items = []
        for item in value:
            if len(items) == _MAX_ITEMS:
                notes.append(f"only the first {_MAX_ITEMS} items are shown")
                break
            items.append(_to_json(item, notes, depth + 1))
        return items
    return str(value)
