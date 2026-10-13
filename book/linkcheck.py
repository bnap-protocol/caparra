"""Fail when a built mdBook links to a relative path that does not exist.

Usage: python3 -I book/linkcheck.py book/book

Checks every href and src attribute in the generated HTML. External URLs,
in-page anchors and site-absolute paths (the 404 page uses those) are
skipped. Standard library only.
"""
import os
import re
import sys

ATTR = re.compile(r'(?:href|src)="([^"]+)"')
SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")


def main(root: str) -> int:
    broken = []
    for folder, _, files in os.walk(root):
        for name in sorted(files):
            if not name.endswith(".html"):
                continue
            page = os.path.join(folder, name)
            with open(page, encoding="utf-8") as fh:
                html = fh.read()
            for url in ATTR.findall(html):
                if SCHEME.match(url) or url.startswith(("#", "/")):
                    continue
                target = url.split("#", 1)[0].split("?", 1)[0]
                if target and not os.path.exists(os.path.join(folder, target)):
                    broken.append(f"{os.path.relpath(page, root)}: {url}")
    for line in sorted(set(broken)):
        print(f"broken link: {line}")
    print(f"linkcheck: {len(set(broken))} broken link(s) under {root}")
    return 1 if broken else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1]))
