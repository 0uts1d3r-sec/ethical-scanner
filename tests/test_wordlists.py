"""Wordlist loading and validation."""
import ethical_scanner as core


def test_comments_and_blank_lines_are_skipped(tmp_path):
    f = tmp_path / "w.txt"
    f.write_text("# comment\n\n' OR 1=1--\n  \nadmin'--\n")
    payloads, loaded, skipped, error = core.WordlistManager().load_file(str(f))
    assert error is None
    assert payloads == ["' OR 1=1--", "admin'--"]
    assert (loaded, skipped) == (2, 3)


def test_overlong_lines_are_skipped(tmp_path):
    f = tmp_path / "w.txt"
    f.write_text("ok\n" + "A" * 501 + "\n")
    payloads, _, skipped, _ = core.WordlistManager().load_file(str(f))
    assert payloads == ["ok"] and skipped == 1


def test_only_txt_files_are_accepted(tmp_path):
    f = tmp_path / "w.csv"
    f.write_text("a\n")
    assert core.WordlistManager().load_file(str(f))[3] == "The file must be a .txt"


def test_missing_and_empty_files_report_an_error(tmp_path):
    manager = core.WordlistManager()
    assert manager.load_file(str(tmp_path / "nope.txt"))[3] == "File not found"
    empty = tmp_path / "empty.txt"
    empty.write_text("# only a comment\n")
    assert manager.load_file(str(empty))[3] is not None


def test_apply_and_reset_restore_defaults(tmp_path):
    f = tmp_path / "w.txt"
    f.write_text("custom\n")
    manager = core.WordlistManager()
    assert manager.apply_sql(str(f)) == (True, None, 1)
    assert manager.sql_payloads == ["custom"]
    manager.reset_sql()
    assert manager.sql_payloads == core.DEFAULT_SQL_PAYLOADS


def test_bundled_sample_wordlists_are_valid():
    for name in ("sqli_samples.txt", "xss_samples.txt", "sqli_destructive.txt"):
        path = f"{core.SAMPLES_DIR}/{name}"
        assert core.WordlistManager().load_file(path)[3] is None, name
