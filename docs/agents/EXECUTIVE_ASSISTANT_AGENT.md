# Executive Assistant Agent

## Purpose

Support planning and prioritization: turn a list of tasks/notes (or freeform text)
into a prioritized plan with a suggested focus, surfaced blockers and open questions,
and a blank decision-log template — all for human review.

| | |
|---|---|
| **Risk level** | Low — plans only; no external actions; no fabrication. |
| **Skill level required** | Anyone; output supports a human's planning. |
| **Deployment complexity** | Low — pure Python, deterministic, no external services. |

## Inputs

- `items` (str | list[str], required) — a freeform string (split on newlines/semicolons)
  or a list of task strings. Leading bullet markers are stripped.
- `focus_count` (int, default 3) — how many top-priority items to suggest as focus.

## Outputs

A JSON-serializable dict (`ExecutivePlan`) with `items` (task + priority + is_blocker),
`prioritized_order`, `suggested_focus`, `blockers`, `open_questions`, a blank
`decision_log_template`, and `assumptions`.

## How priorities are derived

- **high** — urgency/blocker signals (urgent, asap, critical, deadline, today, blocked,
  waiting on, depends on, …).
- **low** — deferral signals (someday, later, optional, backlog, nice to have, …).
- **medium** — everything else. Sorting is stable within a priority band.

## Dependencies

None beyond the Python standard library. Deterministic and network-free.

## Example Usage

```python
from agents.executive_assistant_agent import ExecutiveAssistantAgent

agent = ExecutiveAssistantAgent()
plan = agent.plan(
    "Patch the urgent auth vulnerability today\n"
    "Refactor the logging module someday\n"
    "Blocked on security review for the release\n"
    "Should we adopt the new framework?"
)
# -> urgent + blocked tasks rank first, the question is surfaced as an open
#    question, and a blank decision-log template is provided.
```

## Limitations

- **Plans only.** Never sends messages, schedules events, or takes external action
  (AGENTS.md §5).
- **No fabrication.** Priorities come from explicit signals in the text; it invents
  no tasks, dates, or decisions. The decision-log template is blank for the human.
- **Heuristic** keyword classification — review before relying on the ordering.

## Future Improvements

- Effort/impact scoring beyond keyword urgency.
- Due-date parsing (still human-confirmed).
- Optional export of the decision-log entry once a human fills it in.
