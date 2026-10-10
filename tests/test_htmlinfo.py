from sitecheckup.htmlinfo import parse_page

DOC = """<html><head>
<title> My   Page
 Title </title>
<meta name="description" content="A  description">
<meta name="robots" content="NoIndex, follow">
<meta name="generator" content="WordPress 6.4.2">
<link rel="canonical" href="https://example.com/page">
<link rel="stylesheet" href="http://example.com/a.css">
<script src="/app.js"></script>
</head><body><h1>Hello <b>there</b></h1><h1>Second</h1>
<a href="/about">About</a><a>no href</a><img src="http://example.com/i.png">
<object data="/movie.swf"></object>
</body></html>"""


def test_extracts_metadata() -> None:
    info = parse_page(DOC)
    assert info.title == "My Page Title"
    assert info.meta_description == "A description"
    assert info.canonical == "https://example.com/page"
    assert info.h1 == "Hello there"
    assert info.generator == "WordPress 6.4.2"
    assert info.noindex
    assert info.links == ["/about"]
    kinds = {(r.tag, r.url) for r in info.resources}
    assert ("stylesheet", "http://example.com/a.css") in kinds
    assert ("img", "http://example.com/i.png") in kinds
    assert ("object", "/movie.swf") in kinds


def test_active_vs_passive_resources() -> None:
    info = parse_page(DOC)
    active = {r.tag for r in info.resources if r.active}
    assert active == {"stylesheet", "script", "object"}


def test_empty_and_malformed_html() -> None:
    info = parse_page("<p>no head <b>")
    assert info.title is None
    assert not info.noindex
    assert parse_page("").links == []
