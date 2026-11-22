"""Core checks of the scan engine against a local server."""


def types(engine):
    return [v["type"] for v in engine.results]


def test_plain_http_is_reported(serve, scan):
    engine = scan(serve({"/": (200, "<html></html>", {})}))
    assert "Missing HTTPS" in types(engine)


def test_missing_security_headers_are_reported(serve, scan):
    engine = scan(serve({"/": (200, "<html></html>", {})}))
    assert "Header: X-Frame-Options" in types(engine)


def test_present_header_is_not_reported(serve, scan):
    engine = scan(serve({"/": (200, "<html></html>", {"X-Frame-Options": "DENY"})}))
    assert "Header: X-Frame-Options" not in types(engine)


def test_exposed_path_is_reported_as_high(serve, scan):
    engine = scan(serve({"/": (200, "<html></html>", {}), "/admin": (200, "ok", {})}))
    exposed = [v for v in engine.results if v["type"] == "Exposed path"]
    assert exposed and exposed[0]["severity"] == "High"


def test_reflected_xss_in_a_form_is_found(serve, scan):
    form = '<html><form action="/search" method="get"><input name="query"></form></html>'
    routes = {
        "/": (200, form, {}),
        "/search": (200, lambda qs: "<html>" + qs.get("query", [""])[0] + "</html>", {}),
    }
    assert "Reflected XSS (Form)" in types(scan(serve(routes)))


def test_escaped_output_is_not_flagged_as_xss(serve, scan):
    form = '<html><form action="/search" method="get"><input name="query"></form></html>'
    routes = {
        "/": (200, form, {}),
        "/search": (200, lambda qs: "<html>no echo</html>", {}),
    }
    assert "Reflected XSS (Form)" not in types(scan(serve(routes)))
