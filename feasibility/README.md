# Feasibility pilot

A small, reproducible check that RuleForge's core idea works before any AI code is written: can we automatically prove whether a Sigma rule fires on a recorded attack event, and does it still fire when the attack's command line is slightly changed?

## Run it

```bash
git clone https://github.com/SigmaHQ/sigma.git
git -C sigma checkout 07ec293a51695cb1131a2e05260247872b31e1e1   # pinned: 25 Sep 2026
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python pilot_replay.py --sigma ./sigma --out results.json
```

The script only reads files. Events are loaded as data into an in-memory SQLite table, and rules are compiled to SQL with pySigma. Nothing is executed on the host.

## Results (30 Sep 2026, SigmaHQ commit `07ec293`)

| Check | Result |
| --- | --- |
| Windows `process_creation` rules | 1,185 |
| … that ship regression test data | 263 (22%) |
| … that fire on their own recorded event in the SQLite replay | 263 of 263 (4 s total) |

Mutation operators, applied to each rule's recorded event:

| Operator | Rules it applies to | Still detected | Evaded |
| --- | --- | --- | --- |
| Upper-case command line (control) | 263 | 100% | 0 |
| `-flag` → `/flag` | 91 | 76.9% | 21 |
| `/flag` → `-flag` | 115 | 78.3% | 25 |
| Quote insertion (`/create` → `/"create"`) | 109 | 68.8% | 34 |
| Renamed binary (`OriginalFileName` kept) | 263 | 82.1% | 47 |

## Notes and caveats

- Upper-casing never evades, as expected: Sigma matching is case-insensitive by default, so the harness uses `COLLATE NOCASE` columns. It is kept as a control that proves the harness does not report false evasions.
- Every dash/slash evasion happened in a rule that does not use Sigma's `windash` modifier.
- Caret insertion (`c^ertutil`) is deliberately left out: `cmd.exe` strips carets before the child process's command line is logged, so it is not a realistic mutation of a process-creation event.
- Most regression samples contain a single event, so this is a smoke test of the harness, not a recall benchmark. RuleForge adds held-out recordings and benign baselines on top.
- Conversion needs a `REGEXP` function registered in SQLite; about 3% of SigmaHQ rules (keyword-only rules) are not supported by the SQLite backend.
