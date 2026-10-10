"""Tiny, dependency-free HTML metadata extraction."""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser

_ACTIVE_TAGS = frozenset({"script", "iframe", "embed", "object", "stylesheet"})


@dataclass
class Resource:
    """A sub-resource or link reference found in the markup."""

    tag: str
    url: str

    @property
    def active(self) -> bool:
        """True for resources that can execute or restyle the page."""
        return self.tag in _ACTIVE_TAGS


@dataclass
class PageInfo:
    """Metadata extracted from an HTML document."""

    title: str | None = None
    meta_description: str | None = None
    canonical: str | None = None
    h1: str | None = None
    robots_meta: str | None = None
    generator: str | None = None
    links: list[str] = field(default_factory=list)
    resources: list[Resource] = field(default_factory=list)

    @property
    def noindex(self) -> bool:
        """True if a robots meta tag contains ``noindex``."""
        return bool(self.robots_meta and "noindex" in self.robots_meta.lower())


def _clean(text: str) -> str | None:
    cleaned = " ".join(text.split())
    return cleaned or None


class _Collector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.info = PageInfo()
        self._capturing: str | None = None
        self._buffer: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag in {"title", "h1"}:
            if getattr(self.info, tag) is None and self._capturing is None:
                self._capturing = tag
                self._buffer = []
        elif tag == "meta":
            name = a.get("name", "").lower()
            content = a.get("content", "")
            if name == "description" and self.info.meta_description is None:
                self.info.meta_description = _clean(content)
            elif name == "robots" and self.info.robots_meta is None:
                self.info.robots_meta = _clean(content)
            elif name == "generator" and self.info.generator is None:
                self.info.generator = _clean(content)
        elif tag == "link":
            rel = a.get("rel", "").lower().split()
            href = a.get("href", "")
            if "canonical" in rel and self.info.canonical is None:
                self.info.canonical = href.strip() or None
            elif "stylesheet" in rel and href:
                self.info.resources.append(Resource("stylesheet", href))
        elif tag == "a":
            if a.get("href"):
                self.info.links.append(a["href"])
        elif tag in {"script", "img", "iframe", "audio", "video", "source", "embed"}:
            if a.get("src"):
                self.info.resources.append(Resource(tag, a["src"]))
        elif tag == "object" and a.get("data"):
            self.info.resources.append(Resource("object", a["data"]))

    def handle_data(self, data: str) -> None:
        if self._capturing:
            self._buffer.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == self._capturing:
            setattr(self.info, tag, _clean("".join(self._buffer)))
            self._capturing = None


def parse_page(html: str) -> PageInfo:
    """Extract title, meta tags, canonical, first ``<h1>``, links and resources."""
    collector = _Collector()
    collector.feed(html)
    collector.close()
    return collector.info
