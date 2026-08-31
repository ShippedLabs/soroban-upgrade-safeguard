#!/usr/bin/env python3
import sys
import subprocess
import os

def run_cmd(cmd):
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
    return result.returncode, result.stdout.strip(), result.stderr.strip()

def main():
    print("Checking public API changes...")
    
    # 1. Determine base branch (default to origin/main, fallback to HEAD~1)
    base_branch = os.environ.get("BASE_BRANCH", "origin/main")
    
    code, _, _ = run_cmd(f"git rev-parse --verify {base_branch}")
    if code != 0:
        print(f"Base branch {base_branch} not found, falling back to HEAD~1")
        base_branch = "HEAD~1"
        code, _, _ = run_cmd("git rev-parse --verify HEAD~1")
        if code != 0:
            print("No previous commit (HEAD~1) found. Skipping check.")
            sys.exit(0)
            
    # 2. Check if public-api.txt has changed
    snapshot_file = "tests/snapshots/public-api.txt"
    code, diff_output, _ = run_cmd(f"git diff --name-only {base_branch} -- {snapshot_file}")
    
    if snapshot_file not in diff_output:
        print("[PASS] No public API snapshot changes detected.")
        sys.exit(0)
        
    print(f"[WARN] Public API snapshot change detected in {snapshot_file}!")
    
    # 3. Check if version notes were updated
    code, doc_diff, _ = run_cmd(f"git diff --name-only {base_branch} -- docs/api-changes/ docs/version_note.md")
    
    has_note = False
    for line in doc_diff.splitlines():
        if line.startswith("docs/api-changes/") or line == "docs/version_note.md":
            has_note = True
            print(f"[PASS] Found accompanying version note change: {line}")
            
    if not has_note:
        print("[FAIL] Error: Public API changed but no version note was found!")
        print("Please add a note in 'docs/api-changes/' describing the change, or modify 'docs/version_note.md'.")
        sys.exit(1)
        
    print("[PASS] Public API verification passed.")
    sys.exit(0)

if __name__ == "__main__":
    main()
