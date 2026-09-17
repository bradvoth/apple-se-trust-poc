#!/usr/bin/env python3
"""Fetch an Apple support-guide page and print its article text.

The guide serves each topic as a full HTML page whose article body sits between the
<h1> topic heading and the trailing navigation. Extracting that slice and stripping
tags recovers readable prose without executing any JavaScript.
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


def article_html(raw: str) -> str:
    """Return the article slice: from the first <h1> to the end of the content div."""
    m = re.search(r"<h1[^>]*>", raw)
    if not m:
        return raw
    start = m.start()
    # The article ends where the 'previous/next' topic navigation begins.
    for end_pat in (r'<div[^>]*class="[^"]*NextPrev', r'<footer', r'id="footer"'):
        e = re.search(end_pat, raw[start:])
        if e:
            return raw[start:start + e.start()]
    return raw[start:]


def to_text(fragment: str) -> str:
    s = fragment
    s = re.sub(r"(?i)<(script|style)[^>]*>.*?</\1>", " ", s, flags=re.S)
    s = re.sub(r"(?i)<h([1-6])[^>]*>", r"\n\n### ", s)
    s = re.sub(r"(?i)<li[^>]*>", "\n- ", s)
    s = re.sub(r"(?i)<(p|br|/p|/div|/li|/h[1-6]|/ul|/ol|/table|/tr)[^>]*>", "\n", s)
    s = re.sub(r"(?i)<t[dh][^>]*>", " | ", s)
    s = re.sub(r"<[^>]+>", "", s)
    s = html.unescape(s)
    s = re.sub(r"[ \t\xa0]+", " ", s)
    s = re.sub(r" *\n *", "\n", s)
    s = re.sub(r"\n{3,}", "\n\n", s)
    return s.strip()


def main() -> None:
    url = sys.argv[1]
    needle = sys.argv[2].lower() if len(sys.argv) > 2 else ""
    text = to_text(article_html(fetch(url)))
    if not needle:
        print(text)
        return
    paras = [p.strip() for p in text.split("\n") if len(p.strip()) > 25]
    printed = set()
    for i, p in enumerate(paras):
        if needle in p.lower():
            for q in paras[max(0, i - 2): i + 4]:
                if q not in printed:
                    printed.add(q)
                    print("   " + q[:900])
            print("   ---")
    if not printed:
        print(f"   (no paragraph mentioning '{needle}')")


if __name__ == "__main__":
    main()
