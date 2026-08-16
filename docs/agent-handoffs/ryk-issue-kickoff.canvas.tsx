import {
  Button,
  Callout,
  Card,
  CardBody,
  CardHeader,
  Divider,
  Grid,
  H1,
  H2,
  H3,
  Pill,
  Row,
  Spacer,
  Stack,
  Stat,
  Table,
  Text,
  useCanvasAction,
  useCanvasState,
} from "cursor/canvas";

type PackId =
  | "PR-0"
  | "PR-1"
  | "PR-2"
  | "PR-3"
  | "PR-4"
  | "PR-5"
  | "PR-6"
  | "PR-7"
  | "PR-8"
  | "CLOSE";

type Parallelism = "parallel" | "sequential" | "after-phase1" | "close";

type Pack = {
  id: PackId;
  title: string;
  issues: string;
  phase: string;
  parallelism: Parallelism;
  files: string;
  handoffPath: string;
  prompt: string;
};

const PROMPTS: Record<PackId, string> = {
  "PR-0": `Execute pack PR-0 only on christopherkarani/ryk.

Read and follow exactly:
- docs/agent-handoffs/README.md
- docs/agent-handoffs/phases/phase-0.md
- docs/agent-handoffs/issues/PR-0-221.md
- docs/agent-handoffs/prompts/PR-0.md

Fix #221: one-click ryk grok must reach the agent (or one short error + one verified next). No SHIELD UP walls, no tip novel, no audit=degraded on success path.

One PR. Do not fold #215/#220/#145/#195/#196. Branch cursor/<name>-8968. Commit, push, draft PR citing #221.`,

  "PR-1": `Execute pack PR-1 only on christopherkarani/ryk.

Read and follow exactly:
- docs/agent-handoffs/README.md
- docs/agent-handoffs/phases/phase-1.md
- docs/agent-handoffs/issues/PR-1-215.md
- docs/agent-handoffs/prompts/PR-1.md

Fix #215: drop shield banner from almost every command. No banner on success/--quiet/--no-rich/pipe/errors. Rewrite banner tests in src/cli/mod.zig. Close #213 as duplicate after.

Do not fold packs dump (#208) or session SHIELD UP (#145). Branch cursor/<name>-8968. Draft PR citing #215.`,

  "PR-2": `Execute pack PR-2 only on christopherkarani/ryk.

Read and follow exactly:
- docs/agent-handoffs/README.md
- docs/agent-handoffs/phases/phase-1.md
- docs/agent-handoffs/issues/PR-2-217.md
- docs/agent-handoffs/prompts/PR-2.md

Fix #217: TUI no-TTY fallback must be linear (like doctor --tui), not usage error. Align replay --tui; preferably history --live. Invert exit-2 rejection tests.

Do not add new TUI surfaces. Branch cursor/<name>-8968. Draft PR citing #217.`,

  "PR-3": `Execute pack PR-3 only (#205 + #218 in ONE PR) on christopherkarani/ryk.

Read and follow exactly:
- docs/agent-handoffs/README.md
- docs/agent-handoffs/phases/phase-1.md
- docs/agent-handoffs/issues/PR-3-205-218.md
- docs/agent-handoffs/prompts/PR-3.md

Fix start/doctor daemon contradiction (#218) and doctor walls/one-next/no companion-reinstall (#205) with one honest remediation voice.

Do not reopen #145. Branch cursor/<name>-8968. Draft PR citing #205 and #218.`,

  "PR-4": `Execute pack PR-4 only (#207 + #219) on christopherkarani/ryk.

Read and follow exactly:
- docs/agent-handoffs/README.md
- docs/agent-handoffs/phases/phase-2.md
- docs/agent-handoffs/issues/PR-4-207-219.md
- docs/agent-handoffs/prompts/PR-4.md

Fix first-run start jargon (#219) and leftover help nexts / Get protected (#207). Ask-vs-DCG on help start is already fixed — do not re-fix it.

Prefer after PR-3. Branch cursor/<name>-8968. Draft PR citing #207 and #219.`,

  "PR-5": `Execute pack PR-5 only (#206 + #212) on christopherkarani/ryk.

Read and follow exactly:
- docs/agent-handoffs/README.md
- docs/agent-handoffs/phases/phase-2.md
- docs/agent-handoffs/issues/PR-5-206-212.md
- docs/agent-handoffs/prompts/PR-5.md

Honest host lists: drop cursor from stop/uninstall (#206); plugin help honesty for grok/pi, copy only (#212). No fake plugin-pi.

Watch help.zig conflicts with PR-4. Branch cursor/<name>-8968. Draft PR citing #206 and #212.`,

  "PR-6": `Execute pack PR-6 only (#211 + #214) on christopherkarani/ryk. Safe in parallel with PR-0/1/2.

Read and follow exactly:
- docs/agent-handoffs/README.md
- docs/agent-handoffs/phases/phase-2.md
- docs/agent-handoffs/issues/PR-6-211-214.md
- docs/agent-handoffs/prompts/PR-6.md

ryk env --help → real help exit 0 (#211). Bare ryk policy explain → usage like ryk test (#214). Skip #204 (already fixed).

Branch cursor/<name>-8968. Draft PR citing #211 and #214.`,

  "PR-7": `Execute pack PR-7 only (#209 + #220) on christopherkarani/ryk.

Read and follow exactly:
- docs/agent-handoffs/README.md
- docs/agent-handoffs/phases/phase-3.md
- docs/agent-handoffs/issues/PR-7-209-220.md
- docs/agent-handoffs/prompts/PR-7.md

ryk update must replace a real ryk binary (#209). Installer success path curl-and-done; remove leftover eval/doctor homework feel (#220).

Do not fold #221/#207/#205/#211. Branch cursor/<name>-8968. Draft PR citing #209 and #220.`,

  "PR-8": `Execute pack PR-8 only (#210 + #216 + #208′) on christopherkarani/ryk.

Read and follow exactly:
- docs/agent-handoffs/README.md
- docs/agent-handoffs/phases/phase-3.md
- docs/agent-handoffs/issues/PR-8-polish.md
- docs/agent-handoffs/prompts/PR-8.md

Suggestions threshold (#210). DENY-only color on test/explain (#216). Packs default count+one next (#208′). Error banners owned by #215 — do not touch.

Branch cursor/<name>-8968. Draft PR citing #210, #216, #208.`,

  CLOSE: `Triage-only agent on christopherkarani/ryk. Do NOT ship product code.

Read and follow exactly:
- docs/agent-handoffs/README.md
- docs/agent-handoffs/phases/CLOSE.md
- docs/agent-handoffs/prompts/CLOSE.md

Close with evidence comments: #213 (dup of #215), #203 (already fixed), #204 (already fixed), #197 (docs honest; do not expand check enum). Note on #208 that error-banner half is dup of #215.

Do not reopen #144/#145/#146/#193.`,
};

const PACKS: Pack[] = [
  {
    id: "PR-0",
    title: "Grok one-click launch",
    issues: "#221",
    phase: "0 · P1",
    parallelism: "parallel",
    files: "run.zig, sandbox_card, grants",
    handoffPath: "docs/agent-handoffs/issues/PR-0-221.md",
    prompt: PROMPTS["PR-0"],
  },
  {
    id: "PR-1",
    title: "Kill shield banner",
    issues: "#215 (−#213)",
    phase: "1",
    parallelism: "parallel",
    files: "mod.zig shouldShowBanner",
    handoffPath: "docs/agent-handoffs/issues/PR-1-215.md",
    prompt: PROMPTS["PR-1"],
  },
  {
    id: "PR-2",
    title: "TUI linear fallback",
    issues: "#217",
    phase: "1",
    parallelism: "parallel",
    files: "replay.zig, history.zig",
    handoffPath: "docs/agent-handoffs/issues/PR-2-217.md",
    prompt: PROMPTS["PR-2"],
  },
  {
    id: "PR-3",
    title: "Doctor + start honesty",
    issues: "#205 + #218",
    phase: "1",
    parallelism: "sequential",
    files: "doctor.zig, start.zig",
    handoffPath: "docs/agent-handoffs/issues/PR-3-205-218.md",
    prompt: PROMPTS["PR-3"],
  },
  {
    id: "PR-4",
    title: "First-run / help nexts",
    issues: "#207 + #219",
    phase: "2",
    parallelism: "after-phase1",
    files: "start.zig, help.zig",
    handoffPath: "docs/agent-handoffs/issues/PR-4-207-219.md",
    prompt: PROMPTS["PR-4"],
  },
  {
    id: "PR-5",
    title: "Honest host lists",
    issues: "#206 + #212",
    phase: "2",
    parallelism: "after-phase1",
    files: "help/plugin/stop/uninstall",
    handoffPath: "docs/agent-handoffs/issues/PR-5-206-212.md",
    prompt: PROMPTS["PR-5"],
  },
  {
    id: "PR-6",
    title: "Help exit contracts",
    issues: "#211 + #214",
    phase: "2",
    parallelism: "parallel",
    files: "env_schema, policy.zig",
    handoffPath: "docs/agent-handoffs/issues/PR-6-211-214.md",
    prompt: PROMPTS["PR-6"],
  },
  {
    id: "PR-7",
    title: "Installer / update",
    issues: "#209 + #220",
    phase: "3",
    parallelism: "after-phase1",
    files: "install.sh, update.zig",
    handoffPath: "docs/agent-handoffs/issues/PR-7-209-220.md",
    prompt: PROMPTS["PR-7"],
  },
  {
    id: "PR-8",
    title: "Micro polish",
    issues: "#210 + #216 + #208′",
    phase: "3",
    parallelism: "after-phase1",
    files: "suggestions, packs, color",
    handoffPath: "docs/agent-handoffs/issues/PR-8-polish.md",
    prompt: PROMPTS["PR-8"],
  },
  {
    id: "CLOSE",
    title: "Close fixed / dupes",
    issues: "#213 #203 #204 #197",
    phase: "—",
    parallelism: "close",
    files: "comments only",
    handoffPath: "docs/agent-handoffs/phases/CLOSE.md",
    prompt: PROMPTS.CLOSE,
  },
];

function parallelismLabel(p: Parallelism): string {
  switch (p) {
    case "parallel":
      return "PARALLEL wave";
    case "sequential":
      return "ONE agent (shared files)";
    case "after-phase1":
      return "After Phase 0–1";
    case "close":
      return "Close only";
  }
}

function PackCard({
  pack,
  launched,
  onLaunch,
}: {
  pack: Pack;
  launched: boolean;
  onLaunch: () => void;
}) {
  const dispatch = useCanvasAction();
  return (
    <Card>
      <CardHeader
        trailing={
          <Pill active={pack.parallelism === "parallel"} size="sm">
            {parallelismLabel(pack.parallelism)}
          </Pill>
        }
      >
        {pack.id} · {pack.title}
      </CardHeader>
      <CardBody>
        <Stack gap={10}>
          <Row gap={8} wrap>
            <Text tone="secondary" size="small">
              Issues {pack.issues}
            </Text>
            <Text tone="tertiary" size="small">
              Phase {pack.phase}
            </Text>
          </Row>
          <Text tone="secondary" size="small">
            {pack.files}
          </Text>
          <Row gap={8} align="center">
            <Button
              variant="primary"
              disabled={launched}
              onClick={() => {
                dispatch({
                  type: "newComposerChat",
                  userPrompt: pack.prompt,
                });
                onLaunch();
              }}
            >
              {launched ? "Launched" : "Kick off agent"}
            </Button>
            <Button
              variant="ghost"
              onClick={() =>
                dispatch({
                  type: "openFile",
                  path: pack.handoffPath,
                })
              }
            >
              Open handoff
            </Button>
          </Row>
        </Stack>
      </CardBody>
    </Card>
  );
}

export default function RykIssueKickoffCanvas() {
  const dispatch = useCanvasAction();
  const [launched, setLaunched] = useCanvasState<Record<string, boolean>>(
    "launched-packs",
    {},
  );

  const parallelWave = PACKS.filter((p) => p.parallelism === "parallel");
  const sequentialWave = PACKS.filter(
    (p) => p.parallelism === "sequential" || p.parallelism === "after-phase1",
  );
  const closePack = PACKS.find((p) => p.id === "CLOSE")!;

  const mark = (id: PackId) =>
    setLaunched((prev) => ({ ...prev, [id]: true }));

  return (
    <Stack gap={24}>
      <Stack gap={8}>
        <H1>ryk issue kickoff</H1>
        <Text tone="secondary">
          Adversarial triage of 20 open GitHub issues on 0.2.19 / main
          (2026-08-16). 16 actionable across 9 fix packs + 1 close pack. Press
          Kick off agent to open a Composer chat with the handoff prompt
          preloaded.
        </Text>
      </Stack>

      <Row gap={16} wrap>
        <Stat value="20" label="Open issues scanned" />
        <Stat value="16" label="Real / partial" tone="warning" />
        <Stat value="4" label="Close without code" tone="success" />
        <Stat value="4" label="Safe parallel now" tone="info" />
      </Row>

      <Callout tone="info" title="Start these four in parallel">
        PR-0 (#221 P1), PR-1 (#215), PR-2 (#217), and PR-6 (#211+#214) own
        disjoint files. Max concurrency: kick all four, then PR-3, then
        Phase 2–3 fillers.
      </Callout>

      <Callout tone="warning" title="Sequential choke points">
        PR-3 must be one agent (#205+#218 share doctor.zig). Prefer PR-3 before
        PR-4 (first-run nexts). PR-1 owns all banner policy — do not parallelize
        error-banner edits elsewhere. PR-0 alone owns run.zig / sandbox_card.
      </Callout>

      <H2>Parallel wave — kick now</H2>
      <Grid columns={2} gap={12}>
        {parallelWave.map((pack) => (
          <PackCard
            key={pack.id}
            pack={pack}
            launched={!!launched[pack.id]}
            onLaunch={() => mark(pack.id)}
          />
        ))}
      </Grid>

      <H2>Sequential / after Phase 0–1</H2>
      <Grid columns={2} gap={12}>
        {sequentialWave.map((pack) => (
          <PackCard
            key={pack.id}
            pack={pack}
            launched={!!launched[pack.id]}
            onLaunch={() => mark(pack.id)}
          />
        ))}
      </Grid>

      <H2>Close without a fix PR</H2>
      <PackCard
        pack={closePack}
        launched={!!launched.CLOSE}
        onLaunch={() => mark("CLOSE")}
      />

      <Divider />

      <H2>Dependency map</H2>
      <Table
        headers={["Pack", "Issues", "Depends on", "Blocks / enables"]}
        rows={[
          ["PR-0", "#221", "—", "run.zig owners"],
          ["PR-1", "#215", "—", "Closes #213; strips #208 error-banner"],
          ["PR-2", "#217", "—", "replay/history TUI contract"],
          ["PR-3", "#205+#218", "prefer after PR-1 soft", "Enables honest PR-4 nexts"],
          ["PR-4", "#207+#219", "PR-3 preferred", "First-run copy"],
          ["PR-5", "#206+#212", "help.zig vs PR-4", "Host-list honesty"],
          ["PR-6", "#211+#214", "—", "Help exits"],
          ["PR-7", "#209+#220", "Phase 0–1 preferred", "Installer"],
          ["PR-8", "#210+#216+#208′", "PR-1 for #208′", "Polish"],
          ["CLOSE", "#213/#203/#204/#197", "—", "Inbox hygiene"],
        ]}
        striped
      />

      <H2>Verdict table</H2>
      <Table
        headers={["Issue", "Verdict", "Pack"]}
        columnAlign={["left", "left", "left"]}
        rowTone={[
          "danger",
          "warning",
          "warning",
          "warning",
          "warning",
          "info",
          "info",
          "info",
          "info",
          "info",
          "info",
          "neutral",
          "neutral",
          "neutral",
          "neutral",
          "neutral",
          "success",
          "success",
          "success",
          "success",
        ]}
        rows={[
          ["#221", "REAL P1", "PR-0"],
          ["#215", "REAL", "PR-1"],
          ["#217", "REAL", "PR-2"],
          ["#205", "REAL", "PR-3"],
          ["#218", "REAL", "PR-3"],
          ["#219", "REAL", "PR-4"],
          ["#207", "PARTIAL", "PR-4"],
          ["#206", "REAL", "PR-5"],
          ["#212", "REAL", "PR-5"],
          ["#211", "REAL", "PR-6"],
          ["#214", "REAL", "PR-6"],
          ["#209", "REAL", "PR-7"],
          ["#220", "PARTIAL", "PR-7"],
          ["#210", "REAL", "PR-8"],
          ["#216", "REAL", "PR-8"],
          ["#208", "PARTIAL → dump only", "PR-8"],
          ["#213", "DUP of #215", "CLOSE"],
          ["#203", "ALREADY FIXED", "CLOSE"],
          ["#204", "ALREADY FIXED", "CLOSE"],
          ["#197", "ALREADY FIXED", "CLOSE"],
        ]}
        striped
        stickyHeader
      />

      <H3>Handoff docs in repo</H3>
      <Text tone="secondary">
        Full context lives under docs/agent-handoffs/ (phases, per-pack issues,
        prompts). Kickoff buttons preload the prompt and @mention this canvas.
      </Text>
      <Row gap={8} wrap>
        <Button
          variant="secondary"
          onClick={() =>
            dispatch({
              type: "openFile",
              path: "docs/agent-handoffs/README.md",
            })
          }
        >
          Open triage README
        </Button>
        <Spacer />
        <Button
          variant="ghost"
          onClick={() => setLaunched({})}
        >
          Reset launched flags
        </Button>
      </Row>
    </Stack>
  );
}
