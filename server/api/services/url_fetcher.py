"""
URL fetching and text extraction for the AI chat endpoint.

Uses only Python stdlib — no extra dependencies required.
Fetches a URL, strips HTML noise, and returns clean readable text
truncated to a token-safe character budget.
"""

import logging
import re
import urllib.error
import urllib.request
from html.parser import HTMLParser
from typing import Optional

logger = logging.getLogger(__name__)

URL_RE = re.compile(r'https?://[^\s<>"\')\]]+')
_MAX_FETCH_BYTES = 300_000   # read at most 300 KB of raw HTML
_DEFAULT_MAX_CHARS = 6_000   # return at most 6 000 chars of text
_TIMEOUT = 10                # seconds


class _TextExtractor(HTMLParser):
    """Strip HTML to plain text, discarding script/style/nav noise."""

    _SKIP = frozenset({
        'script', 'style', 'head', 'noscript', 'nav', 'footer',
        'aside', 'header', 'form', 'button', 'svg', 'template',
    })

    def __init__(self):
        super().__init__()
        self._skip_depth = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() in self._SKIP:
            self._skip_depth += 1

    def handle_endtag(self, tag):
        if tag.lower() in self._SKIP and self._skip_depth > 0:
            self._skip_depth -= 1

    def handle_data(self, data):
        if not self._skip_depth:
            t = data.strip()
            if t:
                self.parts.append(t)


def extract_urls(text: str) -> list[str]:
    """Return deduplicated list of http/https URLs found in text."""
    seen: dict[str, None] = {}
    for url in URL_RE.findall(text):
        # strip trailing punctuation that's likely not part of the URL
        url = url.rstrip('.,;:!?)\'\"')
        seen[url] = None
    return list(seen)


def fetch_url_text(url: str, max_chars: int = _DEFAULT_MAX_CHARS) -> Optional[str]:
    """
    Fetch `url` and return extracted plain text (up to `max_chars` characters).
    Returns None on any error so callers can skip gracefully.
    """
    try:
        req = urllib.request.Request(
            url,
            headers={
                'User-Agent': (
                    'Mozilla/5.0 (compatible; sigma-ai-bot/1.0; '
                    '+https://github.com/sigma-ai; security-research)'
                ),
                'Accept': 'text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
            },
        )
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            content_type = resp.headers.get('Content-Type', '')
            raw_bytes = resp.read(_MAX_FETCH_BYTES)

        text = raw_bytes.decode('utf-8', errors='replace')

        if 'text/html' in content_type or text.lstrip().startswith('<'):
            parser = _TextExtractor()
            parser.feed(text)
            text = '\n'.join(parser.parts)
        elif 'application/json' in content_type:
            # JSON pages (e.g. NVD API): keep as-is but truncate
            pass

        # Collapse excessive whitespace / blank lines
        text = re.sub(r'[ \t]{2,}', ' ', text)
        text = re.sub(r'\n{3,}', '\n\n', text)
        return text[:max_chars].strip() or None

    except urllib.error.HTTPError as e:
        logger.warning("URL fetch HTTP error %s for %s", e.code, url)
        return None
    except Exception as e:
        logger.warning("URL fetch failed for %s: %s", url, e)
        return None
