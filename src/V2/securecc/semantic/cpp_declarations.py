"""Conservative C/C++ declaration extraction for semantic lint (not a full parser)."""

from __future__ import annotations

import re
from dataclasses import dataclass

_SKIP_STMT = frozenset(
    {
        "if",
        "for",
        "while",
        "switch",
        "return",
        "break",
        "continue",
        "goto",
        "case",
        "default",
        "throw",
        "try",
        "catch",
        "do",
        "else",
        "typedef",
        "using",
        "namespace",
        "class",
        "struct",
        "enum",
        "template",
        "public",
        "private",
        "protected",
        "#",
    }
)

_TYPE_KEYWORDS = frozenset(
    {
        "void",
        "bool",
        "char",
        "wchar_t",
        "char16_t",
        "char32_t",
        "short",
        "int",
        "long",
        "float",
        "double",
        "signed",
        "unsigned",
        "auto",
        "const",
        "volatile",
        "static",
        "register",
        "extern",
        "mutable",
        "thread_local",
    }
)


@dataclass(frozen=True)
class Token:
    kind: str
    text: str
    start: int
    line: int
    col: int


@dataclass(frozen=True)
class Declaration:
    name: str
    type_text: str
    type_family: str
    line: int
    col: int
    stmt_span: tuple[int, int]
    type_span: tuple[int, int]
    init_kind: str
    literal_value: str | None
    init_span: tuple[int, int] | None
    multi_declarator: bool
    scope: str
    is_auto: bool
    is_pointer: bool
    is_array: bool


def _line_col(source: str, index: int) -> tuple[int, int]:
    line = source.count("\n", 0, index) + 1
    last_nl = source.rfind("\n", 0, index)
    col = index - (last_nl + 1) + 1
    return line, col


def tokenize(source: str) -> list[Token]:
    tokens: list[Token] = []
    i = 0
    n = len(source)
    while i < n:
        ch = source[i]
        if ch in " \t\r\n":
            if ch == "\n":
                line, col = _line_col(source, i)
                tokens.append(Token("newline", "\n", i, line, col))
            i += 1
            continue
        if ch == "/" and i + 1 < n:
            if source[i + 1] == "/":
                end = source.find("\n", i)
                if end == -1:
                    break
                i = end
                continue
            if source[i + 1] == "*":
                end = source.find("*/", i + 2)
                i = end + 2 if end != -1 else n
                continue
        if ch in '"\'':
            quote = ch
            j = i + 1
            while j < n:
                if source[j] == "\\":
                    j += 2
                    continue
                if source[j] == quote:
                    j += 1
                    break
                j += 1
            text = source[i:j]
            kind = "string" if quote == '"' else "char"
            line, col = _line_col(source, i)
            tokens.append(Token(kind, text, i, line, col))
            i = j
            continue
        if ch.isdigit() or (ch == "." and i + 1 < n and source[i + 1].isdigit()):
            j = i
            while j < n and (source[j].isdigit() or source[j] in ".eE+-fFlL"):
                j += 1
            text = source[i:j]
            line, col = _line_col(source, i)
            tokens.append(Token("number", text, i, line, col))
            i = j
            continue
        if ch.isalpha() or ch == "_":
            j = i
            while j < n and (source[j].isalnum() or source[j] in "_"):
                j += 1
            text = source[i:j]
            line, col = _line_col(source, i)
            tokens.append(Token("identifier", text, i, line, col))
            i = j
            continue
        if i + 1 < n and source[i : i + 2] in {"::", "->", "++", "--", "==", "!=", "<=", ">=", "&&", "||", "<<", ">>"}:
            text = source[i : i + 2]
            line, col = _line_col(source, i)
            tokens.append(Token("punct", text, i, line, col))
            i += 2
            continue
        line, col = _line_col(source, i)
        tokens.append(Token("punct", ch, i, line, col))
        i += 1
    return tokens


def _classify_type(type_text: str, *, is_auto: bool, is_pointer: bool, is_array: bool) -> str:
    if is_pointer:
        return "POINTER"
    if is_array:
        return "COLLECTION"
    t = type_text.replace("const", "").replace("volatile", "").strip()
    t_lower = t.lower()
    if is_auto:
        return "AUTO"
    if re.search(r"\bvector\s*<|\barray\s*<|\[\s*\]", t_lower):
        return "COLLECTION"
    if re.search(r"\bstring\b", t_lower):
        return "TEXT"
    if re.search(r"\bbool\b", t_lower):
        return "BOOL"
    if re.search(r"\bchar\b", t_lower) and "string" not in t_lower:
        return "CHAR"
    if re.search(r"\b(float|double|long double)\b", t_lower):
        return "FLOAT"
    if re.search(r"\b(short|int|long|size_t|uint\w*)\b", t_lower) or "unsigned" in t_lower:
        return "INTEGER"
    if re.search(r"\b\w+\s*\*", t):
        return "POINTER"
    if t and re.match(r"^[A-Za-z_]\w*(::\w+)*$", t.replace(" ", "")):
        if t_lower in _TYPE_KEYWORDS or "::" in t:
            if "string" in t_lower:
                return "TEXT"
            if t_lower.endswith("int") or "int" in t_lower.split():
                return "INTEGER"
        return "USER"
    return "UNKNOWN"


def _init_info(source: str, tokens: list[Token], eq_index: int) -> tuple[str, str | None, tuple[int, int] | None]:
    if eq_index < 0 or eq_index + 1 >= len(tokens):
        return "NONE", None, None
    j = eq_index + 1
    while j < len(tokens) and tokens[j].kind in {"newline"}:
        j += 1
    if j >= len(tokens):
        return "NONE", None, None
    tok = tokens[j]
    if tok.kind == "string":
        return "LITERAL_STR", tok.text, (tok.start, tok.start + len(tok.text))
    if tok.kind == "char":
        return "LITERAL_CHAR", tok.text, (tok.start, tok.start + len(tok.text))
    if tok.kind == "number":
        text = tok.text
        kind = "LITERAL_FLOAT" if any(x in text for x in ".eE") else "LITERAL_INT"
        return kind, text, (tok.start, tok.start + len(text))
    if tok.kind == "identifier" and tok.text in {"true", "false"}:
        return "LITERAL_BOOL", tok.text, (tok.start, tok.start + len(tok.text))
    if tok.kind == "identifier":
        return "CALL", None, None
    return "NONE", None, None


def _try_parse_declaration(source: str, tokens: list[Token], start: int, end: int) -> Declaration | None:
    stmt_tokens = [t for t in tokens[start : end + 1] if t.kind != "newline"]
    if not stmt_tokens:
        return None
    if stmt_tokens[0].kind == "identifier" and stmt_tokens[0].text in _SKIP_STMT:
        return None
    if stmt_tokens[0].text == "#":
        return None

    eq_index = next((i for i, t in enumerate(stmt_tokens) if t.text == "="), -1)
    semi = stmt_tokens[-1]
    if semi.text != ";":
        return None

    core = stmt_tokens[: eq_index if eq_index >= 0 else -1]
    if eq_index >= 0:
        core = stmt_tokens[:eq_index]

    # Find declarator name: last identifier before [ or = that isn't a keyword type part
    name_idx = -1
    for i in range(len(core) - 1, -1, -1):
        t = core[i]
        if t.kind != "identifier":
            continue
        if t.text in _TYPE_KEYWORDS and i > 0:
            continue
        if t.text in {"std", "namespace"}:
            continue
        name_idx = i
        break
    if name_idx <= 0:
        return None

    name_tok = core[name_idx]
    type_tokens = core[:name_idx]
    if not type_tokens:
        return None

    type_text = source[type_tokens[0].start : type_tokens[-1].start + len(type_tokens[-1].text)]
    type_text = re.sub(r"\s+", " ", type_text).strip()
    is_auto = any(t.text == "auto" for t in type_tokens)
    is_pointer = any(t.text == "*" for t in core[name_idx:])
    is_array = any(t.text == "[" for t in core[name_idx:])

    commas = sum(1 for t in core if t.text == ",")
    init_kind, literal_value, init_span = _init_info(source, stmt_tokens, eq_index)

    type_family = _classify_type(type_text, is_auto=is_auto, is_pointer=is_pointer, is_array=is_array)
    if is_auto and init_kind != "NONE":
        type_family = "AUTO"

    stmt_start = stmt_tokens[0].start
    stmt_end = semi.start + 1
    type_span = (type_tokens[0].start, type_tokens[-1].start + len(type_tokens[-1].text))

    return Declaration(
        name=name_tok.text,
        type_text=type_text,
        type_family=type_family,
        line=name_tok.line,
        col=name_tok.col,
        stmt_span=(stmt_start, stmt_end),
        type_span=type_span,
        init_kind=init_kind,
        literal_value=literal_value,
        init_span=init_span,
        multi_declarator=commas > 0,
        scope="local",
        is_auto=is_auto,
        is_pointer=is_pointer,
        is_array=is_array,
    )


def extract_declarations(source: str, tokens: list[Token] | None = None) -> list[Declaration]:
    tokens = tokens or tokenize(source)
    decls: list[Declaration] = []
    depth = 0
    i = 0
    n = len(tokens)
    while i < n:
        t = tokens[i]
        if t.text == "{":
            depth += 1
            i += 1
            continue
        if t.text == "}":
            depth = max(0, depth - 1)
            i += 1
            continue
        if depth < 1:
            i += 1
            continue
        if t.text != ";":
            stmt_start = i
            while i < n and tokens[i].text != ";":
                i += 1
            if i >= n:
                break
            decl = _try_parse_declaration(source, tokens, stmt_start, i)
            if decl:
                decls.append(decl)
            i += 1
            continue
        i += 1
    return decls
