#!/usr/bin/env python3
"""Fetch a readme.io documentation page and print its article body.

The docs are served as an HTML shell with the article embedded as a JSON string in a
`"body": "..."` field, so decoding that field recovers the prose without executing
JavaScript.
"""
import html
import re
import sys
import urllib.request

UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15"


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", "replace")


def body_text(raw: str) -> str:
    m = re.search(r'"body"\s*:\s*"((?:[^"\\]|\\.)*)"', raw)
    if not m:
        # Fall back to any paragraph-level prose on the page.
        m2 = re.findall(r"<p[^>]*>(.{40,800}?)</p>", raw, re.S)
        return "\n".join(
            html.unescape(re.sub(r"<[^>]+>", "", p)).strip() for p in m2
        )
    txt = m.group(1).encode().decode("unicode_escape", "replace")
    txt = re.sub(r"(?i)<li[^>]*>", "\n- ", txt)
    txt = re.sub(r"(?i)<h([1-6])[^>]*>", r"\n\n### ", txt)
    txt = re.sub(r"(?i)<(p|br|/p|/div|/li|/h[1-6]|/tr|/ul|/ol)[^>]*>", "\n", txt)
    txt = re.sub(r"(?i)<t[dh][^>]*>", " | ", txt)
    txt = re.sub(r"<[^>]+>", "", txt)
    txt = html.unescape(txt)
    txt = re.sub(r"[ \t\xa0]+", " ", txt)
    txt = re.sub(r" *\n *", "\n", txt)
    txt = re.sub(r"\n{3,}", "\n\n", txt)
    return txt.strip()


if __name__ == "__main__":
    url = sys.argv[1]
    needle = sys.argv[2].lower() if len(sys.argv) > 2 else ""
    text = body_text(fetch(url))
    if not needle:
        print(text)
    else:
        hit = False
        for line in text.split("\n"):
            if needle in line.lower():
                hit = True
                print("   " + line.strip()[:900])
        if not hit:
            print(f"   (no line mentioning '{needle}')")
            print("   --- first 900 chars ---")
            print("   " + text[:900])
