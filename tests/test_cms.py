"""CMS detection: regression tests for the false positive on a lone /admin/."""

MAGENTO_HTML = "<html><script>Mage.Cookies.path='/'</script></html>"
WORDPRESS_HTML = '<html><link href="/wp-content/themes/x/style.css"></html>'


def recommendations(engine, cms):
    return [v for v in engine.results if v["type"] == f"[{cms}] Recommendation"]


def test_one_generic_signal_is_not_a_cms(serve, scan):
    url = serve({"/": (200, "<html>plain</html>", {}), "/admin/": (200, "admin", {})})
    engine = scan(url)
    assert engine.detected_cms == []
    assert recommendations(engine, "Magento") == []


def test_two_signals_detect_magento(serve, scan):
    url = serve({"/": (200, MAGENTO_HTML, {}), "/admin/": (200, "admin", {})})
    engine = scan(url)
    assert [(c["name"], c["confidence"]) for c in engine.detected_cms] == [("Magento", 50)]


def test_recommendation_rows_are_distinct(serve, scan):
    url = serve({"/": (200, MAGENTO_HTML, {}), "/admin/": (200, "admin", {})})
    descriptions = [v["description"] for v in recommendations(scan(url), "Magento")]
    assert len(descriptions) == 2
    assert len(set(descriptions)) == 2


def test_two_signals_detect_wordpress(serve, scan):
    url = serve({"/": (200, WORDPRESS_HTML, {}), "/wp-login.php": (200, "login", {})})
    names = [c["name"] for c in scan(url).detected_cms]
    assert names == ["WordPress"]
