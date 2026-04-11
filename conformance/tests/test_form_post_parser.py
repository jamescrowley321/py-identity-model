"""Tests for the form_post HTML parser in conformance/run_tests.py.

These tests target the ``_FormPostParser`` class and the ``_parse_form_post``
helper, which together extract the action URL and hidden fields from an
``oidcc-client-test-formpost-*`` response. The parser is invoked by
``drive_rp_authorize`` whenever the conformance suite returns an HTML page
in response to an auth request — this is the ``response_mode=form_post``
path that the Form Post RP profile exercises.

The crash bug fixed in the companion commit (relative ``action`` URL causing
``httpx.InvalidURL``) is verified here by asserting the parser still returns
the relative URL verbatim — resolution against the response base URL is the
caller's responsibility, not the parser's.
"""

from __future__ import annotations

from run_tests import _FormPostParser, _parse_form_post


# ---------------------------------------------------------------------------
# _FormPostParser — direct class tests
# ---------------------------------------------------------------------------


def test_parser_captures_action_method_and_hidden_fields() -> None:
    html = """
    <html><body>
      <form method="POST" action="https://op.example.com/test/a/alias/callback">
        <input type="hidden" name="code" value="abc123" />
        <input type="hidden" name="state" value="xyz" />
        <input type="submit" value="Submit" />
      </form>
    </body></html>
    """
    parser = _FormPostParser()
    parser.feed(html)

    assert parser.action == "https://op.example.com/test/a/alias/callback"
    assert parser.method == "POST"
    assert parser.fields == {"code": "abc123", "state": "xyz"}


def test_parser_preserves_relative_action_url_verbatim() -> None:
    """Relative action URLs are the parser's concern to surface; the
    caller is expected to resolve them against the response base URL."""
    html = '<form method="POST" action="/test/a/alias/callback"></form>'
    parser = _FormPostParser()
    parser.feed(html)

    assert parser.action == "/test/a/alias/callback"
    assert parser.method == "POST"


def test_parser_ignores_non_hidden_inputs() -> None:
    """Only ``type=hidden`` inputs should be captured; text/submit/etc. are
    presentation-only and must not leak into the POST payload."""
    html = """
    <form method="POST" action="https://op.example.com/cb">
      <input type="hidden" name="id_token" value="eyJabc" />
      <input type="text" name="username" value="alice" />
      <input type="password" name="password" value="secret" />
      <input type="submit" value="Go" />
      <input name="no_type" value="should_also_be_ignored" />
    </form>
    """
    parser = _FormPostParser()
    parser.feed(html)

    assert parser.fields == {"id_token": "eyJabc"}


def test_parser_ignores_hidden_input_without_name() -> None:
    html = """
    <form method="POST" action="https://op.example.com/cb">
      <input type="hidden" value="orphan_no_name" />
      <input type="hidden" name="state" value="s" />
    </form>
    """
    parser = _FormPostParser()
    parser.feed(html)

    assert parser.fields == {"state": "s"}


def test_parser_handles_empty_value_attribute() -> None:
    html = '<form method="POST" action="x"><input type="hidden" name="empty" value="" /></form>'
    parser = _FormPostParser()
    parser.feed(html)

    # An empty-value field is legitimate in the OIDC form-post response
    # (e.g. an access_token field that is intentionally blank for a
    # code-only flow). It must be preserved as "" rather than dropped.
    assert parser.fields == {"empty": ""}


def test_parser_second_form_resets_fields() -> None:
    """If the HTML contains two forms, the later one replaces the earlier.

    The suite only ever emits one form per response, but this makes the
    behaviour deterministic if that ever changes.
    """
    html = """
    <form method="GET" action="/first"><input type="hidden" name="a" value="1" /></form>
    <form method="POST" action="/second"><input type="hidden" name="b" value="2" /></form>
    """
    parser = _FormPostParser()
    parser.feed(html)

    assert parser.method == "POST"
    assert parser.action == "/second"
    assert parser.fields == {"b": "2"}


def test_parser_handles_malformed_html_without_crashing() -> None:
    """HTMLParser is tolerant of malformed markup — verify it doesn't raise."""
    html = (
        '<form method="POST" action="/cb"><input type="hidden" name="a" value="unclosed'
    )
    parser = _FormPostParser()
    # The key assertion is that feed() does not raise.
    parser.feed(html)
    assert parser.method == "POST"
    assert parser.action == "/cb"


# ---------------------------------------------------------------------------
# _parse_form_post — helper behaviour
# ---------------------------------------------------------------------------


def test_parse_form_post_returns_action_and_fields_for_valid_post() -> None:
    html = """
    <form method="POST" action="https://op.example.com/cb">
      <input type="hidden" name="code" value="abc" />
      <input type="hidden" name="state" value="xyz" />
    </form>
    """
    result = _parse_form_post(html)

    assert result is not None
    action_url, fields = result
    assert action_url == "https://op.example.com/cb"
    assert fields == {"code": "abc", "state": "xyz"}


def test_parse_form_post_returns_none_for_get_form() -> None:
    """A GET form is not a form-post response — the parser should say so."""
    html = '<form method="GET" action="/cb"><input type="hidden" name="a" value="1" /></form>'
    assert _parse_form_post(html) is None


def test_parse_form_post_returns_none_for_form_without_method() -> None:
    """HTML default form method is GET — treat a method-less form as GET."""
    html = '<form action="/cb"><input type="hidden" name="a" value="1" /></form>'
    assert _parse_form_post(html) is None


def test_parse_form_post_returns_none_for_post_without_action() -> None:
    """A POST form with no action attribute has no target — not usable."""
    html = '<form method="POST"><input type="hidden" name="a" value="1" /></form>'
    assert _parse_form_post(html) is None


def test_parse_form_post_returns_none_for_html_without_any_form() -> None:
    html = "<html><body><p>no form here</p></body></html>"
    assert _parse_form_post(html) is None


def test_parse_form_post_case_insensitive_method() -> None:
    """The HTML spec is case-insensitive on form method attributes."""
    html = '<form method="post" action="/cb"><input type="hidden" name="a" value="1" /></form>'
    result = _parse_form_post(html)

    assert result is not None
    assert result[0] == "/cb"
    assert result[1] == {"a": "1"}


def test_parse_form_post_handles_relative_action_url() -> None:
    """Relative action URLs are returned as-is — resolution is the caller's job.

    This is the scenario behind the httpx.InvalidURL crash fix: the parser
    surfaces the relative URL, and drive_rp_authorize resolves it against
    the response URL before POSTing.
    """
    html = '<form method="POST" action="/test/a/alias/callback"><input type="hidden" name="a" value="1" /></form>'
    result = _parse_form_post(html)

    assert result is not None
    assert result[0] == "/test/a/alias/callback"
