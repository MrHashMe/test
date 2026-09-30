"""RuleForge feasibility pilot: replay and mutation-test SigmaHQ rules.

What it does
------------
1. Finds Windows process_creation rules in a SigmaHQ checkout that ship
   regression test data (``regression_tests_path``).
2. Compiles each rule to SQLite with pySigma's SQLite backend.
3. Replays the rule against its own recorded event (JSON sample) in an
   in-memory SQLite table and checks that it fires.
4. Applies text-only mutation operators to the recorded event and reports
   how many rules still fire (a first measure of evasion robustness).

Nothing is executed on a host: events are data, rules are SQL queries.

Usage
-----
    git clone https://github.com/SigmaHQ/sigma.git
    git -C sigma checkout 07ec293a51695cb1131a2e05260247872b31e1e1
    pip install -r requirements.txt
    python pilot_replay.py --sigma ./sigma --out results.json
"""

import argparse
import collections
import glob
import json
import os
import re
import sqlite3
import time

import yaml
from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection


# --------------------------------------------------------------------------
# Loading recorded events
# --------------------------------------------------------------------------

def load_events(path):
    """Load a SigmaHQ regression JSON sample into flat {field: value} rows.

    Some samples hold several pretty-printed JSON objects back to back, so
    the file is decoded object by object instead of with ``json.loads``.
    """
    text = open(path, encoding="utf-8").read().strip()
    decoder = json.JSONDecoder()
    objects, i = [], 0
    while i < len(text):
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            break
        obj, i = decoder.raw_decode(text, i)
        objects.extend(obj if isinstance(obj, list) else [obj])

    rows = []
    for obj in objects:
        event = obj.get("Event", obj)
        row = {}
        if isinstance(event.get("EventData"), dict):
            row.update({k: v for k, v in event["EventData"].items()
                        if not isinstance(v, (dict, list))})
        system = event.get("System", {})
        if "EventID" in system:
            eid = system["EventID"]
            row["EventID"] = eid.get("#text") if isinstance(eid, dict) else eid
        if "Channel" in system:
            row["Channel"] = system["Channel"]
        if not row:
            row = {k: v for k, v in obj.items() if not isinstance(v, (dict, list))}
        rows.append(row)
    return rows


# --------------------------------------------------------------------------
# Replay: run compiled SQL against events
# --------------------------------------------------------------------------

def _regexp(pattern, value):
    if value is None:
        return False
    try:
        return re.search(pattern, str(value)) is not None
    except re.error:
        return False


def count_hits(queries, rows):
    """Return the number of matching rows for a rule's SQL queries.

    Columns are TEXT COLLATE NOCASE because Sigma string matching is
    case-insensitive by default, and SQLite needs a REGEXP function for
    Sigma's ``re`` modifier.
    """
    con = sqlite3.connect(":memory:")
    con.create_function("REGEXP", 2, _regexp)
    referenced = set(re.findall(
        r"\b([A-Za-z][A-Za-z0-9_]*)\b(?=\s*(?:LIKE|=|REGEXP|IN|<|>|IS))",
        " ".join(queries)))
    columns = sorted({c for r in rows for c in r} | referenced)
    con.execute("CREATE TABLE logs (" +
                ",".join(f'"{c}" TEXT COLLATE NOCASE' for c in columns) + ")")
    for r in rows:
        names = ",".join(f'"{k}"' for k in r)
        marks = ",".join("?" * len(r))
        con.execute(f"INSERT INTO logs ({names}) VALUES ({marks})",
                    [str(v) for v in r.values()])
    hits = sum(len(con.execute(q).fetchall()) for q in queries)
    con.close()
    return hits


# --------------------------------------------------------------------------
# Mutation operators (text-only, literature-grounded)
# --------------------------------------------------------------------------

def _with(row, field, value):
    new = dict(row)
    new[field] = value
    return new


def uppercase_cmdline(row):
    """Control operator: Sigma matching is case-insensitive, so this
    should never evade a rule unless it uses the ``cased`` modifier."""
    return _with(row, "CommandLine", str(row.get("CommandLine", "")).upper())


def dash_to_slash(row):
    """Option-character substitution: ' -flag' becomes ' /flag'."""
    cl = str(row.get("CommandLine", ""))
    return _with(row, "CommandLine", re.sub(r"(?<=\s)-(?=[A-Za-z])", "/", cl))


def slash_to_dash(row):
    """Option-character substitution: ' /flag' becomes ' -flag'."""
    cl = str(row.get("CommandLine", ""))
    return _with(row, "CommandLine", re.sub(r"(?<=\s)/(?=[A-Za-z])", "-", cl))


def quote_insertion(row):
    """Quote insertion, e.g. schtasks /create -> schtasks /"create"
    (an insertion evasion described by Uetz et al., USENIX Security 2024)."""
    cl = str(row.get("CommandLine", ""))
    return _with(row, "CommandLine",
                 re.sub(r"(?<=\s)([/-])([A-Za-z]{2,})", r'\1"\2"', cl, count=1))


def renamed_image(row):
    """Copy-and-rename the binary; OriginalFileName (from the PE header)
    is kept, as it would be in a real renamed copy."""
    img = str(row.get("Image", ""))
    if "\\" not in img:
        return dict(row)
    return _with(row, "Image", img.rsplit("\\", 1)[0] + "\\svc_update.exe")


MUTATIONS = {
    "uppercase_cmdline (control)": uppercase_cmdline,
    "dash_to_slash": dash_to_slash,
    "slash_to_dash": slash_to_dash,
    "quote_insertion": quote_insertion,
    "renamed_image": renamed_image,
}


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--sigma", required=True, help="path to a SigmaHQ/sigma checkout")
    parser.add_argument("--category", default="process_creation")
    parser.add_argument("--out", default="results.json")
    args = parser.parse_args()

    backend = sqliteBackend()
    pattern = os.path.join(args.sigma, "rules", "windows", args.category, "*.yml")
    rule_paths = sorted(glob.glob(pattern))

    stats = collections.Counter(rules_in_category=len(rule_paths))
    cases, failures = [], []
    started = time.time()
    for path in rule_paths:
        source = open(path, encoding="utf-8").read()
        rule = yaml.safe_load(source)
        rt_path = rule.get("regression_tests_path")
        if not rt_path:
            continue
        stats["with_regression_data"] += 1
        sample = os.path.join(args.sigma, os.path.dirname(rt_path), f"{rule['id']}.json")
        if not os.path.exists(sample):
            stats["missing_json_sample"] += 1
            continue
        try:
            queries = backend.convert(SigmaCollection.from_yaml(source))
        except Exception as exc:  # backend limitation, recorded not hidden
            stats["conversion_errors"] += 1
            failures.append({"rule": os.path.basename(path), "stage": "convert", "error": str(exc)[:200]})
            continue
        rows = load_events(sample)
        if count_hits(queries, rows) > 0:
            stats["fires_on_own_sample"] += 1
        else:
            failures.append({"rule": os.path.basename(path), "stage": "replay", "error": "no match"})
        cases.append((os.path.basename(path), queries, rows, "windash" in source))
    stats["replay_seconds"] = round(time.time() - started, 1)

    mutation_results = {}
    for name, operator in MUTATIONS.items():
        applicable = survived = 0
        evaded_without_windash = evaded_with_windash = 0
        for _, queries, rows, uses_windash in cases:
            mutated = [operator(r) for r in rows]
            if mutated == rows:
                continue
            applicable += 1
            if count_hits(queries, mutated) > 0:
                survived += 1
            elif uses_windash:
                evaded_with_windash += 1
            else:
                evaded_without_windash += 1
        mutation_results[name] = {
            "applicable_rules": applicable,
            "still_detected": survived,
            "detection_rate": round(survived / applicable, 3) if applicable else None,
            "evaded_rules_without_windash": evaded_without_windash,
            "evaded_rules_with_windash": evaded_with_windash,
        }

    report = {"stats": dict(stats), "mutations": mutation_results, "failures": failures}
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    print(json.dumps(report["stats"], indent=2))
    print(f"{'operator':<30}{'applicable':>11}{'detected':>10}{'rate':>8}")
    for name, r in mutation_results.items():
        rate = f"{r['detection_rate']:.1%}" if r["detection_rate"] is not None else "n/a"
        print(f"{name:<30}{r['applicable_rules']:>11}{r['still_detected']:>10}{rate:>8}")


if __name__ == "__main__":
    main()
