#!/bin/sh
# Judge for rename-save: a persisted IDA database must exist in the workspace
# (beside the target, or wherever the tool under test saves it) and its
# function names must now include decrypt_me. Runs in the workspace with the
# run environment, so idax is on PATH and uses the run's daemon.
dbs=$(find . -path ./.claude -prune -o -path ./.grok -prune -o -path ./.agents -prune -o \
  \( -name '*.i64' -o -name '*.idb' \) -type f -print)
[ -n "$dbs" ] || { echo "no .i64 database was saved" >&2; exit 1; }
for db in $dbs; do
  out=$(idax exec "$db" --timeout 300 \
    'print("\n".join(ida_funcs.get_func_name(f) for f in idautils.Functions()))' 2>&1)
  # 2: analysis still running (a rename can trigger it); the names are there.
  echo "$out" | grep -q decrypt_me && exit 0
done
echo "decrypt_me not found in $(echo $dbs)" >&2
exit 1
