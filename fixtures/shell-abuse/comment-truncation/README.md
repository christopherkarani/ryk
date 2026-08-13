# glued-hash comment truncation cannot hide a payload

Exercises the Zig shell engine (`shell.eval:`) without executing anything.

- `echo safe#; rm -rf /` — the `#` is glued to a word, so it is literal text,
  not a comment. The engine must split at `;` and deny the `rm -rf /` segment.
- `echo x#$(rm -rf /)` — the `#` must not suppress command-substitution
  extraction; the `$(…)` body is collected and denied.

Legitimate word-start comments (`echo foo # comment`) are covered by the
shell-engine security corpus (`src/shell_engine/security_regressions.jsonl`)
and still evaluate as `echo foo`.
