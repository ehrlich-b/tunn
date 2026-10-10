#!/usr/bin/env python3
"""Build a static local preview; never contact a service or modify runtime code."""
import argparse
from html.parser import HTMLParser
from pathlib import Path
import shutil
import evaluate
from render_results import render

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[1]


class LocalPage(HTMLParser):
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in {"form", "iframe", "object", "embed", "base"}:
            raise ValueError(f"Unavailable action or embedded content: {tag}")
        for key in ("href", "src", "action", "srcset", "poster"):
            value = attrs.get(key, "")
            if value and (":" in value or value.startswith(("/", "\\")) or ".." in value):
                raise ValueError(f"Non-local reference: {value}")
        if any(key.startswith("on") for key in attrs):
            raise ValueError("Inline event handlers are unavailable")


def build(out, input_path=None):
    out = Path(out).resolve()
    scratch = (REPO / ".scratch").resolve()
    if not out.is_relative_to(scratch) or out == scratch:
        raise ValueError("Preview output must be a child of this clone's .scratch/")
    out.mkdir(parents=True, exist_ok=True)
    report = evaluate.evaluate(evaluate.read_json(input_path or ROOT / "fixtures" / "synthetic.json"))
    pages = 0
    for source in sorted((ROOT / "site").iterdir()):
        if source.is_symlink() or not source.is_file() or source.suffix not in {".html", ".css", ".js"}:
            raise ValueError(f"Unexpected site asset: {source.name}")
        if source.suffix == ".html":
            LocalPage().feed(source.read_text())
            pages += 1
        target = out / source.name
        if target.is_symlink():
            raise ValueError("Refusing a symlink output")
        if source.name == "results.html":
            html = source.read_text().replace("@@RESULTS@@", render(report))
            LocalPage().feed(html)
            target.write_text(html)
        else:
            shutil.copyfile(source, target)
    return pages


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--input", type=Path, help="Private local observations; defaults to the labelled synthetic fixture")
    args = parser.parse_args()
    try:
        pages = build(args.out, args.input)
    except (ValueError, OSError) as exc:
        parser.exit(2, f"build: {exc}\n")
    print(f"Built {pages} local prototype pages in {args.out}")


if __name__ == "__main__":
    main()
