# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""A malformed line gets one JSON-RPC error, and the loop keeps reading.

``mcp/transport.py`` documents that "malformed input never crashes the loop".
Measured on main at 2090519, five lines crashed it: a ``tools/call`` whose
``params`` was ``1`` or ``"x"`` and a top-level ``[]`` (``AttributeError``), an
id of 5000 digits (``ValueError``, the int-digit limit) and 100000 open
brackets (``RecursionError``). One invalid byte did too, under the strict stdin
decoder an ordinary UTF-8 locale gives, and the valid lines read with it were
never answered.

The host on the other end of stdio is untrusted (DESIGN.md §5 boundary 2) and
the loop is an agent's whole tool surface, so a line that ends it takes every
tool down at once. Each case here asserts the answer and that the next request
is still served.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, NoReturn

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from mcp.server import ToolRegistry, build_default_registry
from mcp.transport import INVALID_PARAMS, INVALID_REQUEST, PARSE_ERROR, serve, utf8_lines

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _tools_call(params: str) -> str:
    """A ``tools/call`` with id 2 whose ``params`` is the raw JSON text given."""
    return '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":' + params + "}"


def _initialize(req_id: str) -> str:
    """An ``initialize`` whose id is the raw JSON text given."""
    return '{"jsonrpc":"2.0","id":' + req_id + ',"method":"initialize"}'


#: The int-digit limit that turns a long id into a ``ValueError`` (default 4300;
#: 0 disables it). One of the measured lines depends on it refusing 5000 digits.
_MAX_DIGITS = sys.get_int_max_str_digits()
_REFUSES_5000_DIGITS = 0 < _MAX_DIGITS < 5000

#: The fixed text of each error, so no exception text reaches the host.
_MESSAGES = {
    PARSE_ERROR: "parse error",
    INVALID_REQUEST: "invalid JSON-RPC request",
    INVALID_PARAMS: "'params' must be an object",
}

#: The five lines measured to crash ``serve``, the code each must now get, and
#: the id that answer must carry: ``None`` wherever no id can be read.
_MEASURED_LINES: dict[str, tuple[str, int, int | None]] = {
    "params-int": (_tools_call("1"), INVALID_PARAMS, 2),
    "params-str": (_tools_call('"x"'), INVALID_PARAMS, 2),
    "top-level-array": ("[]", INVALID_REQUEST, None),
    "id-past-int-digit-limit": (_initialize("9" * 5000), PARSE_ERROR, None),
    "nesting-past-recursion-limit": ("[" * 100_000, PARSE_ERROR, None),
}

#: The one case whose premise belongs to the interpreter rather than the server.
_DIGITS_CASE = "id-past-int-digit-limit"
_APPLICABLE = {
    name: case
    for name, case in _MEASURED_LINES.items()
    if name != _DIGITS_CASE or _REFUSES_5000_DIGITS
}
_MEASURED = [
    pytest.param(
        *case,
        id=name,
        marks=pytest.mark.skipif(
            name not in _APPLICABLE,
            reason="this interpreter's int-digit limit does not refuse 5000 digits",
        ),
    )
    for name, case in _MEASURED_LINES.items()
]


def _reject_constant(token: str) -> NoReturn:
    raise AssertionError(f"the server wrote {token}, which is not JSON")


def _decode(text: str) -> list[dict[str, Any]]:
    """Every line the server wrote, parsed as strict JSON."""
    return [json.loads(line, parse_constant=_reject_constant) for line in text.splitlines()]


def _serve(registry: ToolRegistry, lines: list[str]) -> list[dict[str, Any]]:
    out = io.StringIO()
    serve(registry, iter(lines), out)
    return _decode(out.getvalue())


def _call(req_id: int) -> str:
    """A valid ``tools/call`` that reads the fixture file."""
    params = {"name": "read_text_file", "arguments": {"path": "note.txt"}}
    return json.dumps({"jsonrpc": "2.0", "id": req_id, "method": "tools/call", "params": params})


def _assert_error(response: dict[str, Any], code: int, req_id: object) -> None:
    assert response["jsonrpc"] == "2.0"
    assert "result" not in response
    assert response["error"] == {"code": code, "message": _MESSAGES[code]}
    assert response["id"] == req_id


def _assert_read(response: dict[str, Any], req_id: int) -> None:
    assert response["id"] == req_id
    assert response["result"]["isError"] is False
    assert response["result"]["content"][0]["json"]["content"] == "hello"


@pytest.fixture(scope="module")
def registry(tmp_path_factory: pytest.TempPathFactory) -> ToolRegistry:
    root = tmp_path_factory.mktemp("mcp-root")
    (root / "note.txt").write_text("hello", encoding="utf-8")
    return build_default_registry(root)


# --------------------------------------------------------------------------
# The five measured crashes
# --------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.parametrize(("line", "code", "req_id"), _MEASURED)
def test_each_measured_crash_gets_one_error(
    registry: ToolRegistry, line: str, code: int, req_id: int | None
) -> None:
    (response,) = _serve(registry, [line + "\n"])
    _assert_error(response, code, req_id)


@pytest.mark.security
@pytest.mark.parametrize(("line", "code", "req_id"), _MEASURED)
def test_a_valid_request_after_a_measured_crash_is_answered(
    registry: ToolRegistry, line: str, code: int, req_id: int | None
) -> None:
    """The loop survives the line: the tool call after it runs and is answered."""
    error, answer = _serve(registry, [line + "\n", _call(7) + "\n"])
    _assert_error(error, code, req_id)
    _assert_read(answer, 7)


@pytest.mark.security
def test_one_loop_survives_every_measured_line_in_turn(registry: ToolRegistry) -> None:
    """All five through a single ``serve`` call, each followed by a request."""
    cases = list(_APPLICABLE.values())
    lines = [text for i, (line, _, _) in enumerate(cases) for text in (line, _call(100 + i))]
    responses = _serve(registry, lines)
    assert len(responses) == 2 * len(cases)
    for i, (_, code, req_id) in enumerate(cases):
        _assert_error(responses[2 * i], code, req_id)
        _assert_read(responses[2 * i + 1], 100 + i)


# --------------------------------------------------------------------------
# The same classes, beyond the five measured lines
# --------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.parametrize("params", ["[1]", "true", "1.5", "null", "[]"])
def test_params_that_are_not_an_object_are_invalid_params(
    registry: ToolRegistry, params: str
) -> None:
    """``[1]``, ``true`` and ``1.5`` crashed too; ``null`` and ``[]`` were already -32602."""
    (response,) = _serve(registry, [_tools_call(params)])
    _assert_error(response, INVALID_PARAMS, 2)


@pytest.mark.security
@pytest.mark.parametrize(
    "line",
    ["1", '"x"', "null", "true", '[{"jsonrpc":"2.0","id":1,"method":"initialize"}]'],
    ids=["number", "string", "null", "bool", "batch"],
)
def test_a_message_that_is_not_an_object_is_an_invalid_request(
    registry: ToolRegistry, line: str
) -> None:
    """Each crashed on ``.get``. A batch is refused whole, not unpacked."""
    (response,) = _serve(registry, [line])
    _assert_error(response, INVALID_REQUEST, None)


@pytest.mark.security
@pytest.mark.parametrize("req_id", ["true", "false", "{}", "[]", "[1]", "1e400"])
def test_an_id_that_is_not_a_string_number_or_null_is_never_echoed(
    registry: ToolRegistry, req_id: str
) -> None:
    """Each was echoed back. ``1e400`` decodes to ``inf``, which wrote ``Infinity``."""
    (response,) = _serve(registry, [_initialize(req_id)])
    _assert_error(response, INVALID_REQUEST, None)


@pytest.mark.security
@pytest.mark.parametrize(
    "req_id",
    ['"abc"', "0", "-7", "1.5", "null", "9" * (_MAX_DIGITS or 4300)],
    ids=["string", "zero", "negative", "fraction", "null", "at-the-digit-limit"],
)
def test_a_valid_id_is_still_echoed(registry: ToolRegistry, req_id: str) -> None:
    """No over-correction: every id JSON-RPC allows still round-trips, up to the digit limit."""
    (response,) = _serve(registry, [_initialize(req_id)])
    assert response["id"] == json.loads(req_id)
    assert "error" not in response


@pytest.mark.security
@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity"])
def test_a_non_json_constant_is_a_parse_error(registry: ToolRegistry, token: str) -> None:
    """``json.loads`` accepts all three by default; this request used to be answered."""
    line = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"x":' + token + "}}"
    (response,) = _serve(registry, [line])
    _assert_error(response, PARSE_ERROR, None)


@pytest.mark.security
def test_nesting_past_the_recursion_limit_in_an_object_is_a_parse_error(
    registry: ToolRegistry,
) -> None:
    (response,) = _serve(registry, ['{"a":' * 100_000])
    _assert_error(response, PARSE_ERROR, None)


# --------------------------------------------------------------------------
# Bytes that are not UTF-8
# --------------------------------------------------------------------------


@pytest.mark.security
def test_an_invalid_byte_is_a_parse_error_on_its_line_only(registry: ToolRegistry) -> None:
    """Outside a string or inside one, the line is not JSON text, and nothing else is lost."""
    stream = io.BytesIO(
        b'{"jsonrpc":"2.0","id":1,"method":"initialize"}\n'
        b"\xff\xfe\n"
        b'{"jsonrpc":"2.0","id":2,"method":"x\xff"}\n' + _call(3).encode() + b"\n"
    )
    out = io.StringIO()
    serve(registry, utf8_lines(stream), out)
    first, outside, inside, last = _decode(out.getvalue())
    assert first["id"] == 1
    assert "result" in first
    _assert_error(outside, PARSE_ERROR, None)
    _assert_error(inside, PARSE_ERROR, None)
    _assert_read(last, 3)


@pytest.mark.security
def test_a_lone_surrogate_in_a_text_line_is_a_parse_error(registry: ToolRegistry) -> None:
    """The same check holds for a caller that hands ``serve`` text directly."""
    error, answer = _serve(registry, ['{"jsonrpc":"2.0","id":1,"method":"\udcff"}', _call(2)])
    _assert_error(error, PARSE_ERROR, None)
    _assert_read(answer, 2)


@pytest.mark.security
def test_the_entrypoint_survives_an_invalid_byte_under_strict_decoding(tmp_path: Path) -> None:
    """``python -m mcp.transport`` itself, with stdin decoded the way macOS decodes it.

    ``PYTHONIOENCODING=utf-8:strict`` stands in for an ordinary UTF-8 locale.
    Before the fix, this exited 1 with ``UnicodeDecodeError`` and wrote
    nothing, not even the answer to the valid line that preceded the bad byte.
    """
    (tmp_path / "note.txt").write_text("hello", encoding="utf-8")
    env = {**os.environ, "PYTHONIOENCODING": "utf-8:strict", "MCP_ROOT": str(tmp_path)}
    stdin = b'{"jsonrpc":"2.0","id":1,"method":"initialize"}\n\xff\xfe\n' + _call(2).encode()
    result = subprocess.run(
        [sys.executable, "-m", "mcp.transport"],
        input=stdin,
        capture_output=True,
        timeout=60,
        check=False,
        cwd=_REPO_ROOT,
        env=env,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    first, error, answer = _decode(result.stdout.decode("ascii"))
    assert first["id"] == 1
    assert "result" in first
    _assert_error(error, PARSE_ERROR, None)
    _assert_read(answer, 2)


# --------------------------------------------------------------------------
# The invariant, over generated messages
# --------------------------------------------------------------------------

_JSON = st.recursive(
    st.none()
    | st.booleans()
    | st.integers()
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text(max_size=16),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=8), children, max_size=4)
    ),
    max_leaves=12,
)

#: Envelopes whose members are each present or not, drawn from any JSON value,
#: so the checks on ``jsonrpc``, ``id`` and ``method`` see everything.
_ENVELOPES = st.fixed_dictionaries(
    {},
    optional={"jsonrpc": st.just("2.0") | _JSON, "id": _JSON, "method": _JSON, "params": _JSON},
)

#: Well-formed envelopes around a known method. Wild members stop at the first
#: check, so without these the generated values would never reach the method
#: handlers or the ``params`` checks.
_CALLS = st.fixed_dictionaries(
    {
        "jsonrpc": st.just("2.0"),
        "method": st.sampled_from(["initialize", "tools/list", "tools/call", "nope"]),
    },
    optional={"id": st.integers() | st.text(max_size=8), "params": _JSON},
)

#: ``tools/call`` requests that reach ``dispatch``, so the generated arguments
#: meet the allow-list, the policy gate and the tool's own validation.
_TOOL_CALLS = st.fixed_dictionaries(
    {
        "jsonrpc": st.just("2.0"),
        "id": st.integers(),
        "method": st.just("tools/call"),
        "params": st.fixed_dictionaries(
            {
                "name": st.just("read_text_file") | st.text(max_size=16),
                "arguments": st.fixed_dictionaries(
                    {"path": st.just("note.txt") | st.text(max_size=64) | _JSON}
                )
                | _JSON,
            }
        ),
    }
)

#: One run per family. Drawn as a single ``one_of``, 220 of 300 examples stopped
#: at the envelope check and no generated call read the file.
_FAMILIES = {
    "any-json-value": _JSON,
    "wild-envelope": _ENVELOPES,
    "known-method": _CALLS,
    "tool-dispatch": _TOOL_CALLS,
}


@pytest.mark.security
@pytest.mark.parametrize("family", list(_FAMILIES))
@settings(max_examples=200, derandomize=True, deadline=None)
@given(data=st.data())
def test_no_message_ends_the_loop(registry: ToolRegistry, family: str, data: st.DataObject) -> None:
    """Whatever arrives, at most one strict-JSON answer, and the next request is served.

    The first line gets no answer only when it has no ``id``, as a notification, and
    an answer carries the request's own id or null, never one the server made up.
    """
    message = data.draw(_FAMILIES[family], label="message")
    responses = _serve(registry, [json.dumps(message), _call(999)])
    assert len(responses) in (1, 2)
    if len(responses) == 1:
        assert isinstance(message, dict)
        assert "id" not in message
    else:
        echoed = responses[0]["id"]
        assert echoed is None or (isinstance(message, dict) and echoed == message.get("id"))
    for response in responses:
        assert response["jsonrpc"] == "2.0"
        assert "id" in response
        assert ("result" in response) != ("error" in response)
    _assert_read(responses[-1], 999)
