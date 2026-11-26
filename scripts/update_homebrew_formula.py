#!/usr/bin/env python3
"""Generate the Homebrew formula for a published macOS release."""

import argparse
import hashlib
import re
from pathlib import Path


ASSETS = {
    "aarch64-apple-darwin": "soroban-upgrade-safeguard-aarch64-apple-darwin.tar.gz",
    "x86_64-apple-darwin": "soroban-upgrade-safeguard-x86_64-apple-darwin.tar.gz",
}
FORMULA_PATH = Path("Formula/soroban-upgrade-safeguard.rb")
VERSION_PATTERN = re.compile(r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
FORMULA_VERSION_PATTERN = re.compile(r'^  version "(\d+\.\d+\.\d+)"$', re.MULTILINE)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="Release tag, for example v1.2.3")
    parser.add_argument("--repository", required=True, help="GitHub owner/repository")
    parser.add_argument("--asset-dir", type=Path, required=True, help="Directory containing release archives")
    parser.add_argument("--formula", type=Path, default=FORMULA_PATH, help="Formula output path")
    return parser.parse_args()


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as archive:
        for block in iter(lambda: archive.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def render_formula(version, repository, checksums):
    apple_silicon_url = (
        f"https://github.com/{repository}/releases/download/v{version}/{ASSETS['aarch64-apple-darwin']}"
    )
    intel_url = (
        f"https://github.com/{repository}/releases/download/v{version}/{ASSETS['x86_64-apple-darwin']}"
    )
    return f'''class SorobanUpgradeSafeguard < Formula
  desc "Check for breaking changes in Soroban contract upgrades"
  homepage "https://github.com/{repository}"
  version "{version}"

  on_macos do
    if Hardware::CPU.arm?
      url "{apple_silicon_url}"
      sha256 "{checksums['aarch64-apple-darwin']}"
    else
      url "{intel_url}"
      sha256 "{checksums['x86_64-apple-darwin']}"
    end
  end

  def install
    bin.install "soroban-upgrade-safeguard"
  end

  test do
    assert_match "Usage:", shell_output("#{{bin}}/soroban-upgrade-safeguard --help")
  end
end
'''


def main():
    args = parse_args()
    match = VERSION_PATTERN.fullmatch(args.version)
    if not match:
        raise SystemExit(f"Unsupported release version: {args.version!r}; expected vMAJOR.MINOR.PATCH")
    version = ".".join(match.groups())

    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository):
        raise SystemExit(f"Invalid GitHub repository: {args.repository!r}")

    args.formula.parent.mkdir(parents=True, exist_ok=True)
    if args.formula.exists():
        current = FORMULA_VERSION_PATTERN.search(args.formula.read_text(encoding="utf-8"))
        if current and tuple(map(int, current.group(1).split("."))) > tuple(map(int, version.split("."))):
            print(f"Skipping {version}; formula is already at {current.group(1)}")
            return

    checksums = {}
    for target, asset_name in ASSETS.items():
        archive = args.asset_dir / asset_name
        if not archive.is_file():
            raise SystemExit(f"Missing release archive: {archive}")
        checksums[target] = sha256(archive)

    args.formula.write_text(
        render_formula(version, args.repository, checksums), encoding="utf-8"
    )
    print(f"Updated {args.formula} to {version}")


if __name__ == "__main__":
    main()