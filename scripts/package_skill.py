#!/usr/bin/env python3
import argparse
import zipfile
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parent.parent
INCLUDED_FILES = (
    ".env.example",
    ".gitignore",
    "README.md",
    "SKILL.md",
    "agents/openai.yaml",
    "assets/icon.png",
    "references/security-policy.md",
    "scripts/package_skill.py",
    "scripts/vault.py",
    "tests/test_vault.py",
)


def package(output):
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for relative_name in INCLUDED_FILES:
            source = SKILL_ROOT / relative_name
            if not source.is_file() or source.is_symlink():
                raise FileNotFoundError(f"required package file is unsafe or missing: {source}")
            archive.write(source, Path(SKILL_ROOT.name) / relative_name)
    print(f"Packaged safe skill: {output}")


def main():
    parser = argparse.ArgumentParser(description="Package Mema Vault without runtime data")
    parser.add_argument("output", type=Path, nargs="?", default=Path("mema-vault.skill"))
    args = parser.parse_args()
    package(args.output.resolve())


if __name__ == "__main__":
    main()
