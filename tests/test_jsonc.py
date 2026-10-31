import pytest

from mcp_crosswalk import jsonc


def test_plain_json() -> None:
    assert jsonc.loads('{"a": [1, 2]}') == {"a": [1, 2]}


def test_line_and_block_comments_removed() -> None:
    text = '// head\n{ /* inline */ "a": 1, // tail\n "b": /* x */ 2 }'
    assert jsonc.loads(text) == {"a": 1, "b": 2}


def test_trailing_commas_removed() -> None:
    assert jsonc.loads('{"a": [1, 2, ], "b": {"c": 3, }, }') == {"a": [1, 2], "b": {"c": 3}}


def test_comment_markers_inside_strings_are_kept() -> None:
    text = '{"url": "https://x.example/a//b", "c": "/* not */", "d": "a, }"}'
    assert jsonc.loads(text) == {"url": "https://x.example/a//b", "c": "/* not */", "d": "a, }"}


def test_escaped_quotes_in_strings() -> None:
    text = '{"a": "say \\"hi\\" // still string", "b": 1,}'
    assert jsonc.loads(text) == {"a": 'say "hi" // still string', "b": 1}


def test_bom_is_tolerated() -> None:
    assert jsonc.loads('\ufeff{"a": 1}') == {"a": 1}


def test_error_reports_line_number() -> None:
    with pytest.raises(jsonc.JsoncError, match="line 3"):
        jsonc.loads('{\n "a": 1\n "b": 2}')


def test_unterminated_block_comment() -> None:
    with pytest.raises(jsonc.JsoncError, match="unterminated"):
        jsonc.loads('{"a": 1} /* never closed')


def test_comment_keeps_line_numbers() -> None:
    with pytest.raises(jsonc.JsoncError, match="line 4"):
        jsonc.loads('{\n/* one\ntwo */\n "a": }')


def test_huge_integer_is_an_error_not_a_crash() -> None:
    # Review finding 2: Python's int-digit limit raises a plain ValueError, not JSONDecodeError.
    with pytest.raises(jsonc.JsoncError, match="invalid JSON value"):
        jsonc.loads('{"args": [' + "9" * 5000 + "]}")


def test_deep_nesting_is_an_error_not_a_crash() -> None:
    with pytest.raises(jsonc.JsoncError):
        jsonc.loads("[" * 100000 + "]" * 100000)
