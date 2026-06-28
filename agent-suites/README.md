# Agent Suites (git submodules)

This directory vendors the project's standalone agent suites as **git
submodules**, so the command center can pin, version, and update them from their
own repositories.

| Suite | Repo | Agents |
|---|---|---|
| `legal-suite` | [IRsoctierDT/legal-suite](https://github.com/IRsoctierDT/legal-suite) | 11-agent virtual legal office |
| `consumer-protections` | [IRsoctierDT/consumer-protections](https://github.com/IRsoctierDT/consumer-protections) | 14-agent consumer-rights / credit-recovery fleet |

Both are **private** repositories — cloning the submodules requires access.

## First-time setup (after cloning this repo)

```bash
git submodule update --init --recursive
```

## Updating a suite to its latest commit

```bash
git submodule update --remote agent-suites/legal-suite
git add agent-suites/legal-suite        # record the new pinned commit
git commit -m "chore: bump legal-suite submodule"
```

## Activating the agents in this project

Claude Code discovers subagents in `.claude/agents/` (project) and
`~/.claude/agents/` (global). In **this** repo `.claude/agents/` is intentionally
gitignored, so the submodule path is **not** auto-discovered. To use the agents
here, symlink (or copy) each suite's office into `.claude/agents/`:

```bash
ln -s ../../agent-suites/legal-suite/.claude/agents/legal-office \
      .claude/agents/legal-office
ln -s ../../agent-suites/consumer-protections/.claude/agents/consumer-office \
      .claude/agents/consumer-office
```

These links live under the gitignored `.claude/agents/`, so they are local
activation only and are not committed. (This repo ships them pre-linked for the
maintainer's working copy.)

## Why submodules (not copies)

- **Single source of truth** — edit each suite in its own repo; bump the pin here.
- **Independent versioning** — the command center pins a known-good commit.
- **Least coupling** — the suites stay reusable and droppable into any project.
