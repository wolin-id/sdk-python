"""Lightweight W3C Turtle / N-Triples parser for Solid WebID Profile discovery."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from urllib.parse import urldefrag, urljoin, urlsplit

from wolin_id.models import (
    FOAF_NAME_IRI,
    LDP_INBOX_IRI,
    PIM_STORAGE_IRI,
    RDF_TYPE_IRI,
    SOLID_OIDC_ISSUER_IRI,
    VCARD_FN_IRI,
    TurtleParseError,
    WebIdProfile,
)

_RDF_FIRST = "http://www.w3.org/1999/02/22-rdf-syntax-ns#first"
_RDF_REST = "http://www.w3.org/1999/02/22-rdf-syntax-ns#rest"
_RDF_NIL = "http://www.w3.org/1999/02/22-rdf-syntax-ns#nil"
_XSD_NS = "http://www.w3.org/2001/XMLSchema#"


@dataclass(frozen=True, slots=True)
class RdfIri:
    """Named RDF IRI node."""

    value: str


@dataclass(frozen=True, slots=True)
class RdfBlankNode:
    """RDF blank node identifier."""

    label: str


@dataclass(frozen=True, slots=True)
class RdfLiteral:
    """RDF literal value with optional language tag or datatype IRI."""

    value: str
    language: str | None = None
    datatype: str | None = None


RdfSubject = RdfIri | RdfBlankNode
RdfObject = RdfIri | RdfBlankNode | RdfLiteral
RdfTriple = tuple[RdfSubject, RdfIri, RdfObject]


class _TokKind(Enum):
    IRI = auto()
    PNAME = auto()
    BNODE = auto()
    STRING = auto()
    LANGTAG = auto()
    WORD = auto()
    DOT = auto()
    SEMI = auto()
    COMMA = auto()
    LBRACKET = auto()
    RBRACKET = auto()
    LPAREN = auto()
    RPAREN = auto()
    DATATYPE = auto()
    EOF = auto()


@dataclass(frozen=True, slots=True)
class _Token:
    kind: _TokKind
    value: str
    pos: int


def resolve_iri(base_iri: str, reference: str) -> str:
    """Resolve a relative or fragment IRI against `base_iri` per RFC 3986."""
    if not reference:
        doc_iri, _ = urldefrag(base_iri)
        return doc_iri
    if reference.startswith("#"):
        doc_iri, _ = urldefrag(base_iri)
        return f"{doc_iri}{reference}"
    parts = urlsplit(reference)
    if parts.scheme:
        return reference
    doc_iri, _ = urldefrag(base_iri)
    return urljoin(doc_iri, reference)


def _unescape_turtle_string(raw: str, *, is_iri: bool = False) -> str:
    out: list[str] = []
    i = 0
    n = len(raw)
    while i < n:
        ch = raw[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        i += 1
        if i >= n:
            raise TurtleParseError("Trailing backslash escape in Turtle token")
        esc = raw[i]
        i += 1
        if esc == "u":
            hex_part = raw[i : i + 4]
            if len(hex_part) != 4:
                raise TurtleParseError("Incomplete \\uXXXX escape")
            try:
                out.append(chr(int(hex_part, 16)))
            except ValueError as exc:
                raise TurtleParseError(f"Invalid \\uXXXX escape: {hex_part}") from exc
            i += 4
        elif esc == "U":
            hex_part = raw[i : i + 8]
            if len(hex_part) != 8:
                raise TurtleParseError("Incomplete \\UXXXXXXXX escape")
            try:
                out.append(chr(int(hex_part, 16)))
            except ValueError as exc:
                raise TurtleParseError(f"Invalid \\UXXXXXXXX escape: {hex_part}") from exc
            i += 8
        elif not is_iri:
            mapping = {
                "t": "\t",
                "b": "\b",
                "n": "\n",
                "r": "\r",
                "f": "\f",
                '"': '"',
                "'": "'",
                "\\": "\\",
            }
            if esc not in mapping:
                raise TurtleParseError(f"Unsupported string escape '\\{esc}'")
            out.append(mapping[esc])
        else:
            raise TurtleParseError(f"Unsupported IRI escape '\\{esc}'")
    return "".join(out)


def _unescape_pname_local(local: str) -> str:
    out: list[str] = []
    i = 0
    n = len(local)
    while i < n:
        if local[i] == "\\" and i + 1 < n:
            out.append(local[i + 1])
            i += 2
        else:
            out.append(local[i])
            i += 1
    return "".join(out)


def _tokenize_turtle(text: str) -> list[_Token]:
    tokens: list[_Token] = []
    i = 0
    n = len(text)
    punct = {
        ";": _TokKind.SEMI,
        ",": _TokKind.COMMA,
        "[": _TokKind.LBRACKET,
        "]": _TokKind.RBRACKET,
        "(": _TokKind.LPAREN,
        ")": _TokKind.RPAREN,
    }
    terminators = frozenset(
        {" ", "\t", "\r", "\n", ";", ",", "[", "]", "(", ")", "<", '"', "'", "#"}
    )

    while i < n:
        ch = text[i]
        if ch in (" ", "\t", "\r", "\n"):
            i += 1
            continue
        if ch == "#":
            while i < n and text[i] not in ("\n", "\r"):
                i += 1
            continue
        if text.startswith("^^", i):
            tokens.append(_Token(_TokKind.DATATYPE, "^^", i))
            i += 2
            continue
        if ch in punct:
            tokens.append(_Token(punct[ch], ch, i))
            i += 1
            continue
        if ch == "<":
            start = i
            i += 1
            buf: list[str] = []
            while i < n and text[i] != ">":
                if text[i] in ("\n", "\r", " "):
                    raise TurtleParseError(f"Invalid whitespace inside IRIREF at offset {start}")
                buf.append(text[i])
                i += 1
            if i >= n or text[i] != ">":
                raise TurtleParseError(f"Unterminated IRIREF starting at offset {start}")
            i += 1
            iri_val = _unescape_turtle_string("".join(buf), is_iri=True)
            tokens.append(_Token(_TokKind.IRI, iri_val, start))
            continue
        if ch in ('"', "'"):
            start = i
            quote = ch
            long_quote = quote * 3
            if text.startswith(long_quote, i):
                i += 3
                str_buf: list[str] = []
                while i < n and not text.startswith(long_quote, i):
                    if text[i] == "\\" and i + 1 < n:
                        str_buf.append(text[i : i + 2])
                        i += 2
                    else:
                        str_buf.append(text[i])
                        i += 1
                if not text.startswith(long_quote, i):
                    raise TurtleParseError(f"Unterminated multiline literal at offset {start}")
                i += 3
                tokens.append(
                    _Token(_TokKind.STRING, _unescape_turtle_string("".join(str_buf)), start)
                )
            else:
                i += 1
                str_buf = []
                while i < n and text[i] != quote:
                    if text[i] in ("\n", "\r"):
                        raise TurtleParseError(
                            f"Newline inside single-line literal at offset {start}"
                        )
                    if text[i] == "\\" and i + 1 < n:
                        str_buf.append(text[i : i + 2])
                        i += 2
                    else:
                        str_buf.append(text[i])
                        i += 1
                if i >= n or text[i] != quote:
                    raise TurtleParseError(f"Unterminated string literal at offset {start}")
                i += 1
                tokens.append(
                    _Token(_TokKind.STRING, _unescape_turtle_string("".join(str_buf)), start)
                )
            continue
        if ch == "@":
            start = i
            i += 1
            while i < n and (text[i].isalnum() or text[i] == "-"):
                i += 1
            tag = text[start + 1 : i]
            if not tag:
                raise TurtleParseError(f"Empty '@' directive or language tag at offset {start}")
            if tokens and tokens[-1].kind == _TokKind.STRING:
                tokens.append(_Token(_TokKind.LANGTAG, tag, start))
            else:
                tokens.append(_Token(_TokKind.WORD, f"@{tag}", start))
            continue
        if ch == ".":
            if i + 1 < n and text[i + 1].isdigit():
                start = i
                i += 1
                while i < n and (text[i].isalnum() or text[i] in ("+", "-")):
                    i += 1
                tokens.append(_Token(_TokKind.WORD, text[start:i], start))
            else:
                tokens.append(_Token(_TokKind.DOT, ".", i))
                i += 1
            continue

        # Read general word / number / blank node / prefixed name
        start = i
        raw_chars: list[str] = []
        while i < n and text[i] not in terminators:
            if text[i] == "\\" and i + 1 < n:
                raw_chars.append(text[i : i + 2])
                i += 2
            else:
                raw_chars.append(text[i])
                i += 1
        token_str = "".join(raw_chars)
        trailing_dots = 0
        while token_str.endswith(".") and not token_str.endswith("\\."):
            token_str = token_str[:-1]
            trailing_dots += 1

        if token_str:
            if token_str.startswith("_:"):
                label = token_str[2:]
                if not label:
                    raise TurtleParseError(f"Empty blank node label at offset {start}")
                tokens.append(_Token(_TokKind.BNODE, label, start))
            elif ":" in token_str:
                tokens.append(_Token(_TokKind.PNAME, token_str, start))
            else:
                tokens.append(_Token(_TokKind.WORD, token_str, start))

        for d in range(trailing_dots):
            tokens.append(_Token(_TokKind.DOT, ".", i - trailing_dots + d))

    tokens.append(_Token(_TokKind.EOF, "", n))
    return tokens


class _TurtleParser:
    def __init__(self, tokens: list[_Token], base_iri: str) -> None:
        self._tokens = tokens
        self._idx = 0
        self._base_iri = base_iri
        self._prefixes: dict[str, str] = {}
        self._bnode_counter = 0
        self.triples: list[RdfTriple] = []

    def _peek(self) -> _Token:
        return self._tokens[self._idx]

    def _advance(self) -> _Token:
        tok = self._tokens[self._idx]
        if tok.kind != _TokKind.EOF:
            self._idx += 1
        return tok

    def _expect(self, kind: _TokKind) -> _Token:
        tok = self._advance()
        if tok.kind != kind:
            raise TurtleParseError(
                f"Expected {kind.name} at offset {tok.pos}, got {tok.kind.name} ('{tok.value}')"
            )
        return tok

    def _fresh_bnode(self) -> RdfBlankNode:
        self._bnode_counter += 1
        return RdfBlankNode(f"b{self._bnode_counter}")

    def parse(self) -> list[RdfTriple]:
        while self._peek().kind != _TokKind.EOF:
            tok = self._peek()
            if tok.kind == _TokKind.WORD and tok.value == "@prefix":
                self._parse_at_prefix()
            elif tok.kind == _TokKind.WORD and tok.value == "@base":
                self._parse_at_base()
            elif tok.kind == _TokKind.WORD and tok.value.upper() == "PREFIX":
                self._parse_sparql_prefix()
            elif tok.kind == _TokKind.WORD and tok.value.upper() == "BASE":
                self._parse_sparql_base()
            else:
                self._parse_triples_statement()
        return self.triples

    def _parse_at_prefix(self) -> None:
        self._advance()
        pname = self._expect(_TokKind.PNAME)
        if not pname.value.endswith(":"):
            raise TurtleParseError(f"Invalid @prefix declaration '{pname.value}'")
        prefix = pname.value[:-1]
        iri_tok = self._expect(_TokKind.IRI)
        self._expect(_TokKind.DOT)
        self._prefixes[prefix] = resolve_iri(self._base_iri, iri_tok.value)

    def _parse_sparql_prefix(self) -> None:
        self._advance()
        pname = self._expect(_TokKind.PNAME)
        if not pname.value.endswith(":"):
            raise TurtleParseError(f"Invalid PREFIX declaration '{pname.value}'")
        prefix = pname.value[:-1]
        iri_tok = self._expect(_TokKind.IRI)
        self._prefixes[prefix] = resolve_iri(self._base_iri, iri_tok.value)

    def _parse_at_base(self) -> None:
        self._advance()
        iri_tok = self._expect(_TokKind.IRI)
        self._expect(_TokKind.DOT)
        self._base_iri = resolve_iri(self._base_iri, iri_tok.value)

    def _parse_sparql_base(self) -> None:
        self._advance()
        iri_tok = self._expect(_TokKind.IRI)
        self._base_iri = resolve_iri(self._base_iri, iri_tok.value)

    def _parse_triples_statement(self) -> None:
        if self._peek().kind == _TokKind.LBRACKET:
            bnode_subj = self._parse_blank_node_property_list()
            if self._peek().kind != _TokKind.DOT:
                self._parse_predicate_object_list(bnode_subj)
            self._expect(_TokKind.DOT)
            return

        subj = self._parse_subject()
        self._parse_predicate_object_list(subj)
        self._expect(_TokKind.DOT)

    def _parse_subject(self) -> RdfSubject:
        tok = self._peek()
        if tok.kind in (_TokKind.IRI, _TokKind.PNAME):
            return self._parse_iri()
        if tok.kind == _TokKind.BNODE:
            self._advance()
            return RdfBlankNode(tok.value)
        if tok.kind == _TokKind.LPAREN:
            return self._parse_collection()
        raise TurtleParseError(f"Invalid RDF subject '{tok.value}' at offset {tok.pos}")

    def _parse_predicate_object_list(self, subj: RdfSubject) -> None:
        first = True
        while True:
            if not first:
                if self._peek().kind in (_TokKind.DOT, _TokKind.RBRACKET):
                    break
            pred = self._parse_verb()
            self._parse_object_list(subj, pred)
            first = False
            if self._peek().kind == _TokKind.SEMI:
                while self._peek().kind == _TokKind.SEMI:
                    self._advance()
            else:
                break

    def _parse_verb(self) -> RdfIri:
        tok = self._peek()
        if tok.kind == _TokKind.WORD and tok.value == "a":
            self._advance()
            return RdfIri(RDF_TYPE_IRI)
        return self._parse_iri()

    def _parse_object_list(self, subj: RdfSubject, pred: RdfIri) -> None:
        while True:
            obj = self._parse_object()
            self.triples.append((subj, pred, obj))
            if self._peek().kind == _TokKind.COMMA:
                self._advance()
            else:
                break

    def _parse_object(self) -> RdfObject:
        tok = self._peek()
        if tok.kind in (_TokKind.IRI, _TokKind.PNAME):
            return self._parse_iri()
        if tok.kind == _TokKind.BNODE:
            self._advance()
            return RdfBlankNode(tok.value)
        if tok.kind == _TokKind.LBRACKET:
            return self._parse_blank_node_property_list()
        if tok.kind == _TokKind.LPAREN:
            return self._parse_collection()
        if tok.kind == _TokKind.STRING:
            return self._parse_rdf_literal()
        if tok.kind == _TokKind.WORD:
            self._advance()
            val = tok.value
            if val in ("true", "false"):
                return RdfLiteral(val, datatype=f"{_XSD_NS}boolean")
            if val and (val[0].isdigit() or val[0] in ("+", "-", ".")):
                if "e" in val or "E" in val:
                    return RdfLiteral(val, datatype=f"{_XSD_NS}double")
                if "." in val:
                    return RdfLiteral(val, datatype=f"{_XSD_NS}decimal")
                return RdfLiteral(val, datatype=f"{_XSD_NS}integer")
            raise TurtleParseError(f"Unexpected bare word '{val}' at offset {tok.pos}")
        raise TurtleParseError(f"Unexpected token {tok.kind.name} at offset {tok.pos}")

    def _parse_blank_node_property_list(self) -> RdfBlankNode:
        self._expect(_TokKind.LBRACKET)
        bnode = self._fresh_bnode()
        if self._peek().kind != _TokKind.RBRACKET:
            self._parse_predicate_object_list(bnode)
        self._expect(_TokKind.RBRACKET)
        return bnode

    def _parse_collection(self) -> RdfSubject:
        self._expect(_TokKind.LPAREN)
        items: list[RdfObject] = []
        while self._peek().kind != _TokKind.RPAREN:
            if self._peek().kind == _TokKind.EOF:
                raise TurtleParseError("Unterminated '(' RDF collection")
            items.append(self._parse_object())
        self._expect(_TokKind.RPAREN)
        if not items:
            return RdfIri(_RDF_NIL)
        head = self._fresh_bnode()
        curr = head
        for idx, item in enumerate(items):
            self.triples.append((curr, RdfIri(_RDF_FIRST), item))
            if idx == len(items) - 1:
                self.triples.append((curr, RdfIri(_RDF_REST), RdfIri(_RDF_NIL)))
            else:
                nxt = self._fresh_bnode()
                self.triples.append((curr, RdfIri(_RDF_REST), nxt))
                curr = nxt
        return head

    def _parse_rdf_literal(self) -> RdfLiteral:
        str_tok = self._expect(_TokKind.STRING)
        if self._peek().kind == _TokKind.LANGTAG:
            lang = self._advance().value
            return RdfLiteral(str_tok.value, language=lang)
        if self._peek().kind == _TokKind.DATATYPE:
            self._advance()
            dt_iri = self._parse_iri()
            return RdfLiteral(str_tok.value, datatype=dt_iri.value)
        return RdfLiteral(str_tok.value)

    def _parse_iri(self) -> RdfIri:
        tok = self._advance()
        if tok.kind == _TokKind.IRI:
            return RdfIri(resolve_iri(self._base_iri, tok.value))
        if tok.kind == _TokKind.PNAME:
            prefix, local = tok.value.split(":", 1)
            if prefix not in self._prefixes:
                raise TurtleParseError(
                    f"Undefined Turtle prefix '{prefix}:' at offset {tok.pos}"
                )
            return RdfIri(self._prefixes[prefix] + _unescape_pname_local(local))
        raise TurtleParseError(
            f"Expected IRI or PrefixedName at offset {tok.pos}, got '{tok.value}'"
        )


def parse_turtle_triples(content: str | bytes, *, base_iri: str = "") -> list[RdfTriple]:
    """Parse a W3C Turtle or N-Triples document into RDF triples."""
    if isinstance(content, bytes):
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise TurtleParseError(f"Turtle document is not valid UTF-8: {exc}") from exc
    else:
        text = content

    tokens = _tokenize_turtle(text)
    parser = _TurtleParser(tokens, base_iri=base_iri)
    return parser.parse()


def parse_webid_turtle(
    content: str | bytes,
    webid: str,
    *,
    base_iri: str | None = None,
) -> WebIdProfile:
    """Parse a Solid WebID Profile Turtle document (`pim:storage`, `solid:oidcIssuer`)."""
    normalized_webid = webid.strip()
    if not normalized_webid:
        raise TurtleParseError("WebID URI must not be empty")

    effective_base = urldefrag(normalized_webid)[0] if base_iri is None else base_iri
    triples = parse_turtle_triples(content, base_iri=effective_base)

    oidc_issuers: list[str] = []
    storages: list[str] = []
    inboxes: list[str] = []
    seen_issuers: set[str] = set()
    seen_storages: set[str] = set()
    seen_inboxes: set[str] = set()
    display_name: str | None = None

    for subj, pred, obj in triples:
        if not isinstance(subj, RdfIri) or subj.value != normalized_webid:
            continue
        if isinstance(obj, RdfIri):
            if pred.value == SOLID_OIDC_ISSUER_IRI and obj.value not in seen_issuers:
                seen_issuers.add(obj.value)
                oidc_issuers.append(obj.value)
            elif pred.value == PIM_STORAGE_IRI and obj.value not in seen_storages:
                seen_storages.add(obj.value)
                storages.append(obj.value)
            elif pred.value == LDP_INBOX_IRI and obj.value not in seen_inboxes:
                seen_inboxes.add(obj.value)
                inboxes.append(obj.value)
        elif isinstance(obj, RdfLiteral) and display_name is None:
            if pred.value in (FOAF_NAME_IRI, VCARD_FN_IRI):
                display_name = obj.value

    return WebIdProfile(
        webid=normalized_webid,
        oidc_issuers=tuple(oidc_issuers),
        storages=tuple(storages),
        inboxes=tuple(inboxes),
        name=display_name,
    )
