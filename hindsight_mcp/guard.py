"""Read-only enforcement for agent-supplied Cypher.

The point of this MCP server is that an agent gets the *raw* query surface
rather than thirty canned tools, so the guard in front of it is the load-bearing
piece of the design. It has one job: nothing an agent sends may modify the
graph. The store is append-only and deletes run at roughly three nodes per
second, so a single accepted ``CREATE`` is effectively permanent damage.

The scan is deliberately naive-proof rather than clever. Keyword matching on the
raw text is trivially fooled in both directions:

* ``MATCH (n:HsPkg {name: "// let's DELETE this"}) ...`` is a *read*, but a
  regex over the raw text sees ``DELETE`` and would reject it;
* ``MATCH (n:HsPkg {name: "//"}) DELETE n`` is a *write*, but a scanner that
  strips ``//`` comments without knowing about string literals would treat
  everything after the quote as a comment and let the ``DELETE`` through.

So the text is first run through a single scanner pass (:func:`blank_literals`)
that understands string literals, backtick-quoted identifiers and both comment
forms at once, and blanks their contents while preserving offsets. Keyword
scanning then happens on that code-only view, and reported offsets still point
into the query the agent actually sent.

Rejections carry a stable ``code`` and a human-readable ``message`` naming the
offending construct, because the consumer here is a model that is expected to
read the error and fix its own query.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: Clauses a read may begin with. Everything else is either a mutation or a
#: shape this engine does not execute, and saying so up front is cheaper than
#: letting the server produce a generic parse error.
LEADING_CLAUSES = frozenset({"MATCH", "OPTIONAL", "UNWIND", "RETURN", "WITH"})

#: Keyword -> why it is refused. Ordering is irrelevant; the scan reports the
#: earliest *offset*, so an agent is pointed at the first thing to remove.
MUTATION_KEYWORDS: dict[str, str] = {
    "CREATE": "CREATE writes nodes, relationships or indexes",
    "MERGE": "MERGE writes a node or relationship when it does not already exist",
    "DELETE": "DELETE removes data",
    "DETACH": "DETACH DELETE removes data",
    "SET": "SET writes properties or labels",
    "REMOVE": "REMOVE strips properties or labels",
    "DROP": "DROP destroys an index, constraint or graph object",
    "FOREACH": "FOREACH exists only to apply write clauses per element",
    "CALL": "CALL can invoke a procedure that writes; procedures are not exposed",
    "LOAD": "LOAD CSV ingests external data",
    "ALTER": "ALTER is an administrative write",
    "GRANT": "GRANT is an administrative write",
    "REVOKE": "REVOKE is an administrative write",
    "DENY": "DENY is an administrative write",
    "TERMINATE": "TERMINATE is an administrative command",
}

# A keyword only counts when it stands alone as a word. The lookbehind also
# excludes `.` and `$`, so the property access `n.set` and the parameter
# `$create` are not mistaken for clauses. A label literally named `:Set` would
# still be refused; that is the direction to err in, and no label in this graph
# is named after a write clause.
_KEYWORD_RE = re.compile(
    r"(?<![\w.$])(" + "|".join(sorted(MUTATION_KEYWORDS)) + r")(?![\w])",
    re.IGNORECASE,
)

_LEADING_RE = re.compile(r"[A-Za-z_]+")


@dataclass(frozen=True)
class Rejection:
    """Why a query was refused, in a form an agent can act on."""

    code: str
    message: str
    offset: int | None = None
    snippet: str | None = None

    def as_dict(self) -> dict:
        out: dict[str, object] = {"code": self.code, "message": self.message}
        if self.offset is not None:
            out["offset"] = self.offset
        if self.snippet is not None:
            out["snippet"] = self.snippet
        return out

    def __str__(self) -> str:
        where = "" if self.offset is None else f" at offset {self.offset}"
        near = "" if self.snippet is None else f" near: {self.snippet!r}"
        return f"[{self.code}] {self.message}{where}{near}"


class UnsafeCypher(Exception):
    """A query was refused by the read-only guard."""

    def __init__(self, rejection: Rejection) -> None:
        super().__init__(str(rejection))
        self.rejection = rejection


class UnterminatedLiteral(ValueError):
    """A string literal, quoted identifier or block comment never closed."""


def blank_literals(cypher: str) -> str:
    """Return ``cypher`` with literal and comment *contents* replaced by spaces.

    Quotes, backticks and comment markers are themselves blanked too, so the
    result contains only executable syntax. Length is preserved exactly, which
    means an offset into the returned string is also an offset into the input.

    Raises :class:`UnterminatedLiteral` if a literal or block comment runs off
    the end — an unterminated quote is how a scanner gets tricked into reading
    code as data, so it is refused rather than guessed at.
    """
    out: list[str] = []
    i = 0
    n = len(cypher)
    while i < n:
        ch = cypher[i]
        if ch in "'\"":
            quote = ch
            out.append(" ")
            i += 1
            while i < n and cypher[i] != quote:
                # A backslash escape consumes the next character, so \' does
                # not close the literal.
                step = 2 if cypher[i] == "\\" and i + 1 < n else 1
                out.append(" " * step)
                i += step
            if i >= n:
                raise UnterminatedLiteral(f"unterminated {quote} string literal")
            out.append(" ")
            i += 1
            continue
        if ch == "`":
            out.append(" ")
            i += 1
            while i < n:
                if cypher[i] == "`":
                    # A doubled backtick is an escaped backtick inside the name.
                    if i + 1 < n and cypher[i + 1] == "`":
                        out.append("  ")
                        i += 2
                        continue
                    break
                out.append(" ")
                i += 1
            if i >= n:
                raise UnterminatedLiteral("unterminated ` quoted identifier")
            out.append(" ")
            i += 1
            continue
        if cypher.startswith("//", i):
            while i < n and cypher[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if cypher.startswith("/*", i):
            end = cypher.find("*/", i + 2)
            if end == -1:
                raise UnterminatedLiteral("unterminated /* block comment")
            end += 2
            # Newlines are kept so line numbers in any downstream error still
            # line up with the query the agent sent.
            out.append("".join("\n" if c == "\n" else " " for c in cypher[i:end]))
            i = end
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _snippet(cypher: str, offset: int, width: int = 48) -> str:
    start = max(0, offset - width // 3)
    end = min(len(cypher), offset + width)
    text = cypher[start:end].replace("\n", " ").strip()
    return text


def check(cypher: str) -> Rejection | None:
    """``None`` if ``cypher`` is a safe read, otherwise why it is not.

    Checks run mutation-first on purpose. ``MATCH (n:HsPkg {id: 1}) RETURN
    n.name; CREATE (x:Evil)`` is both multi-statement and a mutation, and
    "you tried to write" is the more useful thing to tell an agent than
    "you sent two statements".
    """
    if not cypher or not cypher.strip():
        return Rejection("EMPTY", "the query is empty")

    try:
        code = blank_literals(cypher)
    except UnterminatedLiteral as exc:
        return Rejection(
            "UNTERMINATED",
            f"{exc}; the query cannot be checked for writes and is refused",
        )

    hit = _KEYWORD_RE.search(code)
    if hit is not None:
        word = hit.group(1).upper()
        return Rejection(
            "MUTATION",
            f"this server is read-only and {MUTATION_KEYWORDS[word]}; "
            f"remove the {word} clause",
            offset=hit.start(),
            snippet=_snippet(cypher, hit.start()),
        )

    semi = code.find(";")
    if semi != -1 and code[semi + 1 :].strip():
        return Rejection(
            "MULTI_STATEMENT",
            "only one Cypher statement may be sent per call; "
            "drop everything after the first ';' and issue a second call",
            offset=semi,
            snippet=_snippet(cypher, semi),
        )

    lead = _LEADING_RE.search(code)
    if lead is None:
        return Rejection("EMPTY", "the query contains no executable clause")
    word = lead.group(0).upper()
    if word not in LEADING_CLAUSES:
        allowed = ", ".join(sorted(LEADING_CLAUSES))
        return Rejection(
            "LEADING_CLAUSE",
            f"a read must begin with one of: {allowed}; this one begins with {word}",
            offset=lead.start(),
            snippet=_snippet(cypher, lead.start()),
        )
    return None


def assert_read_only(cypher: str) -> None:
    """Raise :class:`UnsafeCypher` unless ``cypher`` is a safe single read."""
    rejection = check(cypher)
    if rejection is not None:
        raise UnsafeCypher(rejection)


def is_read_only(cypher: str) -> bool:
    return check(cypher) is None


__all__ = [
    "LEADING_CLAUSES",
    "MUTATION_KEYWORDS",
    "Rejection",
    "UnsafeCypher",
    "UnterminatedLiteral",
    "assert_read_only",
    "blank_literals",
    "check",
    "is_read_only",
]
