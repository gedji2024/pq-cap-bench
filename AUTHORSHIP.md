# Authorship and use of AI tools

This repository is the artifact of the paper "Bounded Authority for Hijacked AI Agents: Offline-Verifiable
Post-Quantum Capability Envelopes for Disaster-Monitoring Sensor Networks" by Georges Parfait Djimefo Kapen,
Ranwa Al Mallah and Samuel Pierre (Polytechnique Montréal).

## Roles

- **Authors.** The first author, Georges Parfait Djimefo Kapen, defined the research question and the scope of
  the study, directed all of the work recorded here, and made every decision: threat model, design, choice of
  schemes and baselines, pre-registration, the deviations recorded in `experiments/agents/DEVIATIONS.md`, and
  which results to report. He reviewed the code, the results and the text, and labelled the human-validation
  sample of the agent study. Ranwa Al Mallah and Samuel Pierre supervised the work and reviewed and approved the manuscript.
- **AI tools, used under the first author's direction.** As disclosed in the paper's acknowledgment:
  - Claude Code (Anthropic) wrote and ran the benchmark, simulation, Tamarin and analysis code from written
    instructions by the first author, who reviewed its output;
  - Perplexity Computer assisted in drafting and editing the manuscript and in preparing those instructions;
  - Elicit assisted in the literature search;
  - Microsoft 365 Copilot and Claude Code were used as independent auditors of the manuscript against the code.

The authors take responsibility for all content, data and references.

## How to read the records

- The `Co-authored-by` lines in commit messages record which AI tool assisted with each commit. Every commit is
  authored by the first author.
- In `experiments/agents/DEVIATIONS.md`, `PREREG.md`, `REPORT.md` and commit messages, **"the user"** means the
  first author, and **"Claude" / "the agent running the study"** means the Claude Code coding assistant that
  executed the runs he started, paused and approved. "Session", "permission classifier" and similar terms refer
  to that assistant's environment.
- Files and notes named **`*_BATCH*`** (for example `NEXT_BATCH`, `FINAL_BATCH`, `FIX_BATCH_v0.3.7`,
  `MELON_BATCH_DECISION`) and the `results/next_batch/` and `results/audit_v02/` notes are the first author's
  written work orders to the coding assistant, and the assistant's reports on them.
- References to the `manuscript/v0.2` branch and its files (for example `MELON_BATCH_DECISION.md` or a commit
  hash on that branch) point to the authors' private working branch with the manuscript sources, drafts and
  instructions; it is not part of this public artifact.
- These records are kept verbatim: `PREREG.md` is fixed by the SHA-256 in `REPORT.md`, and the paper cites
  commit `8e2d301`.
