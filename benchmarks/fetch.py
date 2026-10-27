"""
Fetch independent benchmark data into .benchmarks/ (git-ignored; third-party code is never committed).

    python benchmarks/fetch.py              # OWASP BenchmarkPython (pinned) + GHSA case files
    python benchmarks/fetch.py --discover   # also re-query the GitHub Advisory DB and rebuild
                                            # .benchmarks/ghsa/candidates.json (needs `gh auth login`)

Requires git and the GitHub CLI (`gh`) for the GHSA files.
"""
import argparse
import json
import os
import re
import subprocess
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
DATA = os.path.join(ROOT, ".benchmarks")
OWASP_URL = "https://github.com/OWASP-Benchmark/BenchmarkPython.git"
OWASP_COMMIT = "f1291485808b66e20ddb6b01b10dc71b3df8c8ba"
MANIFEST = os.path.join(ROOT, "benchmarks", "realworld", "manifest.json")
CWES = (89, 78, 22, 79, 94, 95, 502, 1336)


def run(cmd, **kw):
    r = subprocess.run(cmd, capture_output=True, **kw)
    if r.returncode:
        raise SystemExit(f"command failed: {' '.join(cmd)}\n{r.stderr.decode(errors='replace')[:400]}")
    return r.stdout


def fetch_owasp():
    dest = os.path.join(DATA, "BenchmarkPython")
    if not os.path.isdir(dest):
        run(["git", "clone", "--filter=blob:none", OWASP_URL, dest])
    run(["git", "-C", dest, "checkout", "--quiet", OWASP_COMMIT])
    head = run(["git", "-C", dest, "rev-parse", "HEAD"]).decode().strip()
    print("OWASP BenchmarkPython at", head)


def fetch_realworld():
    manifest = json.load(open(MANIFEST, encoding="utf-8"))
    n = 0
    for case in manifest["cases"]:
        for rev, sha in (("vulnerable", case["vulnerable_commit"]), ("patched", case["fix_commit"])):
            for site in case["sites"]:
                dest = os.path.join(DATA, "realworld", case["id"], rev, site["file"])
                if os.path.exists(dest):
                    continue
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                body = run(["gh", "api", "-H", "Accept: application/vnd.github.raw",
                            f"repos/{case['repo']}/contents/{site['file']}?ref={sha}"])
                open(dest, "wb").write(body)
                n += 1
    print(f"GHSA case files: {n} downloaded, {len(manifest['cases'])} cases")


def discover():
    """Re-query advisories and apply the mechanical candidate filter (see benchmarks/README.md)."""
    out = os.path.join(DATA, "ghsa")
    os.makedirs(out, exist_ok=True)
    commit_re = re.compile(r"https://github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]{7,40})")
    testy = re.compile(r"(^|/)(tests?|testing|docs?|examples?)/|(^|/)test_[^/]*\.py$|_test\.py$")
    cands, seen = [], set()
    for cwe in CWES:
        advisories = json.loads(run(["gh", "api", "-X", "GET", "advisories", "-f", "ecosystem=pip",
                                     "-f", f"cwes={cwe}", "-f", "per_page=100", "-f", "type=reviewed"]))
        for adv in advisories:
            if adv["ghsa_id"] in seen:
                continue
            seen.add(adv["ghsa_id"])
            commits = [commit_re.search(r).groups() for r in adv.get("references", []) if commit_re.search(r)]
            if len(commits) != 1:
                continue
            owner, repo, sha = commits[0]
            c = json.loads(run(["gh", "api", f"repos/{owner}/{repo}/commits/{sha}"]))
            if len(c["parents"]) != 1:
                continue
            py = [f for f in c["files"] if f["filename"].endswith(".py") and not testy.search(f["filename"])]
            changed = sum(f["additions"] + f["deletions"] for f in py)
            if not py or len(py) > 3 or changed > 80 or any(f["status"] != "modified" for f in py):
                continue
            cands.append({"ghsa": adv["ghsa_id"], "cve": adv.get("cve_id"), "cwe_query": str(cwe),
                          "cwes": [x["cwe_id"] for x in adv.get("cwes", [])],
                          "package": (adv.get("vulnerabilities") or [{}])[0].get("package", {}).get("name"),
                          "summary": adv.get("summary"), "repo": f"{owner}/{repo}",
                          "fix_commit": c["sha"], "vulnerable_commit": c["parents"][0]["sha"],
                          "files": [f["filename"] for f in py], "changed_lines": changed})
    json.dump(cands, open(os.path.join(out, "candidates.json"), "w"), indent=1)
    print(len(cands), "candidates written; note: advisory data changes over time")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--discover", action="store_true")
    ap.add_argument("--skip-owasp", action="store_true")
    args = ap.parse_args()
    os.makedirs(DATA, exist_ok=True)
    if args.discover:
        discover()
    if not args.skip_owasp:
        fetch_owasp()
    fetch_realworld()


if __name__ == "__main__":
    sys.exit(main())
