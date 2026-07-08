# MCP Tool Execution Sandbox

> **Purpose:** Confine MCP tools that execute external commands inside a rootless,
> seccomp/AppArmor-locked container so a compromised or buggy tool cannot reach the
> host, the network, or data outside its lane.
> **Risk level:** Reduces risk (defense in depth); the module itself runs no network.
> **Skill level required:** Intermediate (container runtime + Linux security profiles).
> **Deployment complexity:** Medium — needs a rootless runtime (Podman/Docker) and,
> for full enforcement, a Linux host with seccomp + AppArmor.

Implements **Hardening Roadmap #5** ([`docs/HARDENING_ROADMAP.md`](../../docs/HARDENING_ROADMAP.md)).

## Executive Summary

The MCP tool surface is already **allow-listed**, **path-confined** (`resolve_within`),
and **policy-gated** (`agents/policies`, Roadmap #1) with a **tamper-evident audit log**
(Roadmap #2). This module adds the last layer: for tools that shell out to an external
command, it runs that command inside a locked-down container instead of on the host.

The two layers compose:

```
tools/call ─▶ ToolRegistry.dispatch ─▶ policy gate (WHETHER it runs) ─▶ SandboxRunner (HOW it runs)
                     │                        │                                │
                  audit log  ◀───────────────┴────────────────────────────────┘
```

`mcp.server.sandboxed_command_tool(...)` wraps a command tool so a call that the policy
engine **allows** is then **confined** by `SandboxRunner`.

## Objectives

1. A tool escape cannot touch the host FS beyond the read-only `MCP_ROOT` mount.
2. No unexpected network egress (`--network=none`, deny-network AppArmor rule).
3. No privilege escalation (`--cap-drop=ALL`, `no-new-privileges`, non-root user).
4. Fail closed: a host that cannot confine a tool **refuses** to run it.
5. Staged rollout: **report mode** audits the intended run before enforcement.

## Architecture / Confinement

Every enforced run is `<runtime> run` with:

| Control | Flag | Guarantees |
|---|---|---|
| Default-deny egress | `--network none` | no outbound connections |
| Drop capabilities | `--cap-drop ALL` | no `CAP_*` privileges |
| No privilege regain | `--security-opt no-new-privileges` | setuid can't re-escalate |
| Syscall allow-list | `--security-opt seccomp=profiles/seccomp.json` | deny-by-default syscalls |
| FS/network MAC | `--security-opt apparmor=mcp-tool` | confines paths + denies net |
| Immutable rootfs | `--read-only` | no tampering with the image |
| Writable scratch | `--tmpfs /work:...,noexec,nosuid,nodev` | only ephemeral work area |
| Non-root | `--user 65534:65534` | never root inside |
| Resource caps | `--memory`, `--pids-limit`, `--cpus` | bounds runaway/fork-bomb tools |
| Least-privilege mount | `-v $MCP_ROOT:/data:ro` | only the allow-listed root, read-only |

Profiles live in [`profiles/`](./profiles): `seccomp.json` (deny-by-default) and
`apparmor-mcp-tool`. Both are committed and version-controlled.

## Implementation Steps (enable enforcement on a Linux host)

```bash
# 1. Install a rootless runtime (Podman preferred).
sudo apt-get install -y podman        # or: rootless Docker

# 2. Load the AppArmor profile (Linux only; seccomp is passed by path).
sudo apparmor_parser -r -W mcp/sandbox/profiles/apparmor-mcp-tool

# 3. Run tools in enforce mode (default is the safe report mode).
#    from Python:
#      cfg = SandboxConfig(root=Path(os.environ["MCP_ROOT"]), mode="enforce")
#      runner = SandboxRunner(cfg, audit=AuditLogger("audit.jsonl"))
```

Register a confined command tool:

```python
from mcp.server import ToolRegistry, sandboxed_command_tool

registry.register(
    sandboxed_command_tool(
        "grep_data",
        "grep within the mounted data root (sandboxed)",
        lambda args: ["grep", "-r", str(args["pattern"]), "/data"],
        runner,
    )
)
# external_network tools are default-deny — the operator must allow-list the
# name in the policy bundle before the call reaches the sandbox.
```

## Supported matrix

| Host | seccomp | AppArmor | Behaviour |
|---|---|---|---|
| Linux + Podman/Docker | ✅ | ✅ (profile loaded) | full enforcement |
| Linux + Podman/Docker, no AppArmor | ✅ | ⚠️ skip the flag | partial (seccomp + caps + net) |
| macOS / no runtime | — | — | **report mode audits; enforce mode refuses (fail-closed)** |

## Risks

- **Profile drift:** the seccomp allow-list is curated for a minimal CLI tool; a tool
  needing more syscalls must extend it deliberately (and reviewably). Over-broad
  profiles weaken the control — tune per tool.
- **Runtime dependency:** enforcement needs a rootless runtime; CI/hosts without one
  fall back to report/refuse, never to unsandboxed execution.
- **macOS dev vs Linux enforce:** kernel confinement (seccomp/AppArmor) is Linux-only;
  develop against report mode, enforce in Linux CI / deploy.

## Cost Considerations

No new Python dependency. Runtime cost is one container spawn per external-command tool
call; in-process read-only tools are unaffected. Podman is open-source and rootless.

## Future Enhancements

1. Pin the base image by digest and build a distroless tool image.
2. Per-tool seccomp/AppArmor profile selection driven by the policy bundle.
3. Optional user-namespace remapping and `--userns=keep-id` guidance for Podman.
