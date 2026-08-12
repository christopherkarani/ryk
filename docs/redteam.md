# Red-team

`ryk redteam` is a **fixture engine self-test**. It exercises ryk’s built-in redteam fixture suite against the internal **`builtin:redteam`** policy preset using **synthetic, in-process** attempts (Zig evaluators).

## What it is

- Deterministic local fixtures under `fixtures/` (or installed resource fixtures)
- Synthetic command / file / network / MCP attempts — **no real agent launch**
- Scorecard + optional JSON report with **provenance** so results cannot be mistaken for install assurance

## What it is not

- **Not** a test of your workspace `.ryk/policy.yaml`
- **Not** a test of production hook install / host wiring (shell Evaluate itself is Zig `shell_engine`)
- **Not** proof that PATH wrappers, host hooks, network proxy, or OS-enforced filesystem backends are active
- A **100% score does not mean** your workspace is protected

For protection grade honesty, see [the compatibility matrix](compatibility.md#protection-grades-canonical) and `ryk doctor` (readiness checks are a separate concern).

## Categories

Current fixture categories include prompt injection, secret exfiltration, shell abuse, network exfiltration, filesystem bypass, and MCP tool poisoning.

## Run

```sh
./zig-out/bin/ryk redteam --ci
./zig-out/bin/ryk redteam fixtures --fixture prompt-injection/readme-env-read --ci
```

## JSON Output

```sh
./zig-out/bin/ryk redteam --json --ci > redteam.json
```

JSON includes a top-level `provenance` object, for example:

| Field | Meaning (current suite) |
|-------|-------------------------|
| `suite_kind` | `engine-self-test` |
| `policy` | `builtin:redteam` |
| `policy_path` | `preset:redteam` (not a workspace path) |
| `evaluator` | `zig-in-process` (not `rust-daemon`) |
| `real_action_attempted` | `false` |
| `network_enforcement` | `unavailable` (installed backend not exercised) |
| `uncovered_boundaries` | workspace policy, wrapper PATH, host hooks, proxy, OS filesystem, and OS sandbox attach |

## CI Mode

`--ci` is non-interactive and exits non-zero if a required fixture fails or is unsupported. Use it to gate **engine regressions**, not “current policy is safe.”

## Adding Fixtures

Read [../fixtures/README.md](../fixtures/README.md). Fixtures must use synthetic data, no real secrets, no real LLMs, and no external network services.

## Skipped Or Unsupported

Some fixtures may be platform-gated. A skipped unsupported result means the host lacks the required backend feature; it is not a pass for that protection.
