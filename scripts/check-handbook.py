"""Check local links in a built mdBook and the syntax of its documented examples."""
import re
import subprocess
import tomllib
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit


class Page(HTMLParser):
    def __init__(self, path):
        super().__init__()
        self.ids = set()
        self.urls = []
        self.feed(path.read_text(encoding="utf-8"))
        self.close()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.add(attrs["id"])
        for key in ("href", "src"):
            if key in attrs:
                self.urls.append(attrs[key])


def check_pages():
    build = Path("book").resolve()
    pages = {path: Page(path) for path in build.rglob("*.html")}
    if build / "index.html" not in pages:
        raise SystemExit("Run mdbook build first.")
    failures = []
    checked = 0
    for path, page in pages.items():
        for url in page.urls:
            parts = urlsplit(url)
            if parts.scheme or parts.netloc:
                continue
            link = unquote(parts.path)
            if link.startswith("/fabric/"):
                target = build / link.removeprefix("/fabric/")
            elif link:
                target = (path.parent / link).resolve()
            else:
                target = path
            if target.is_dir():
                target /= "index.html"
            if not target.is_file() or (
                target in pages and parts.fragment and unquote(parts.fragment) not in pages[target].ids
            ):
                failures.append(f"{path.name}: {url}")
            checked += 1
    if failures:
        raise SystemExit("\n".join(failures))
    print(f"Checked {checked} local links and assets across {len(pages)} pages.")


def check_examples():
    checked = 0
    for path in Path("docs").glob("*.md"):
        for lang, code in re.findall(r"^```(sh|toml)\n(.*?)^```", path.read_text(encoding="utf-8"), re.M | re.S):
            if lang == "toml":
                tomllib.loads(code)
            else:
                subprocess.run(["bash", "-n"], input=code, text=True, check=True)
            checked += 1
    print(f"Checked shell and TOML syntax for {checked} examples.")


if __name__ == "__main__":
    check_pages()
    check_examples()
