import re
from PyQt6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont
from PyQt6.QtCore import Qt
from src.gui import theme

class PythonSyntaxHighlighter(QSyntaxHighlighter):
    def __init__(self, document):
        super().__init__(document)

        self.highlightingRules = []

        keywordFormat = QTextCharFormat()
        keywordFormat.setForeground(QColor(theme.PURPLE))
        keywordFormat.setFontWeight(QFont.Weight.Bold)
        keywords = [
            '\\bdef\\b', '\\bclass\\b', '\\bimport\\b', '\\bfrom\\b',
            '\\bif\\b', '\\belif\\b', '\\belse\\b', '\\bfor\\b',
            '\\bwhile\\b', '\\bbreak\\b', '\\bcontinue\\b', '\\breturn\\b',
            '\\bpass\\b', '\\byield\\b', '\\bNone\\b', '\\bTrue\\b', '\\bFalse\\b',
            '\\basync\\b', '\\bawait\\b', '\\band\\b', '\\bor\\b', '\\bnot\\b',
            '\\bis\\b', '\\bin\\b', '\\btry\\b', '\\bexcept\\b', '\\bfinally\\b',
            '\\bwith\\b', '\\bas\\b', '\\bassert\\b', '\\bdel\\b', '\\bglobal\\b',
            '\\bnonlocal\\b', '\\blambda\\b'
        ]
        for pattern in keywords:
            self.highlightingRules.append((re.compile(pattern), keywordFormat))

        builtinFormat = QTextCharFormat()
        builtinFormat.setForeground(QColor(theme.TEAL))
        builtins = [
            '\\bprint\\b', '\\blen\\b', '\\brange\\b', '\\bstr\\b',
            '\\bint\\b', '\\bfloat\\b', '\\bdict\\b', '\\bset\\b', '\\btype\\b',
            '\\bdir\\b', '\\bgetattr\\b', '\\bsetattr\\b', '\\bhasattr\\b'
        ]
        for pattern in builtins:
            self.highlightingRules.append((re.compile(pattern), builtinFormat))

        decoratorFormat = QTextCharFormat()
        decoratorFormat.setForeground(QColor(theme.ACCENT))
        self.highlightingRules.append((re.compile(r'@[^\n]*'), decoratorFormat))

        stringFormat = QTextCharFormat()
        stringFormat.setForeground(QColor(theme.SUCCESS))
        self.highlightingRules.append((re.compile(r'".*"'), stringFormat))
        self.highlightingRules.append((re.compile(r"'.*'"), stringFormat))

        functionFormat = QTextCharFormat()
        functionFormat.setForeground(QColor(theme.ACCENT))
        self.highlightingRules.append((re.compile(r'\b[A-Za-z0-9_]+(?=\()'), functionFormat))

        numberFormat = QTextCharFormat()
        numberFormat.setForeground(QColor(theme.ORANGE))
        self.highlightingRules.append((re.compile(r'\b[0-9]+(\.[0-9]+)?\b'), numberFormat))

        self.commentFormat = QTextCharFormat()
        self.commentFormat.setForeground(QColor(theme.TEXT_FAINT))
        self.commentFormat.setFontItalic(True)
        self.highlightingRules.append((re.compile(r'#[^\n]*'), self.commentFormat))

        self.multiLineStringFormat = QTextCharFormat()
        self.multiLineStringFormat.setForeground(QColor(theme.SUCCESS))
        self.multiLineStringFormat.setFontItalic(True)

    def highlightBlock(self, text):
        for pattern, format in self.highlightingRules:
            for match in pattern.finditer(text):
                self.setFormat(match.start(), match.end() - match.start(), format)

        self.setCurrentBlockState(0)
        
        in_string = False
        start_idx = 0
        if self.previousBlockState() == 1:
            in_string = True
            
        idx = 0
        while idx < len(text):
            if text[idx:idx+3] == '"""' or text[idx:idx+3] == "'''":
                if in_string:
                    self.setFormat(start_idx, idx + 3 - start_idx, self.multiLineStringFormat)
                    in_string = False
                else:
                    in_string = True
                    start_idx = idx
                idx += 3
                continue
            idx += 1
            
        if in_string:
            self.setCurrentBlockState(1)
            self.setFormat(start_idx, len(text) - start_idx, self.multiLineStringFormat)

class JsonSyntaxHighlighter(QSyntaxHighlighter):
    def __init__(self, document):
        super().__init__(document)

        self.highlightingRules = []

        keyFormat = QTextCharFormat()
        keyFormat.setForeground(QColor(theme.ACCENT))
        self.highlightingRules.append((re.compile(r'"[^"]*"\s*:'), keyFormat))

        stringFormat = QTextCharFormat()
        stringFormat.setForeground(QColor(theme.SUCCESS))
        self.highlightingRules.append((re.compile(r':\s*"[^"]*"'), stringFormat))

        numberFormat = QTextCharFormat()
        numberFormat.setForeground(QColor(theme.ORANGE))
        self.highlightingRules.append((re.compile(r'\b[0-9]+(\.[0-9]+)?\b'), numberFormat))

        boolFormat = QTextCharFormat()
        boolFormat.setForeground(QColor(theme.PURPLE))
        self.highlightingRules.append((re.compile(r'\b(true|false|null)\b'), boolFormat))
        
    def highlightBlock(self, text):
        for pattern, format in self.highlightingRules:
            for match in pattern.finditer(text):
                if pattern.pattern == r'"[^"]*"\s*:':
                    s = match.group()
                    idx = s.rfind('"') + 1
                    self.setFormat(match.start(), idx, format)
                elif pattern.pattern == r':\s*"[^"]*"':
                    s = match.group()
                    idx = s.find('"')
                    self.setFormat(match.start() + idx, len(s) - idx, format)
                else:
                    self.setFormat(match.start(), match.end() - match.start(), format)


_C_KEYWORDS = (
    "auto break case char const continue default do double else enum extern float for goto if inline "
    "int long register restrict return short signed sizeof static struct switch typedef union unsigned "
    "void volatile while _Bool bool true false NULL"
)
_CPP_KEYWORDS = _C_KEYWORDS + (
    " alignas alignof catch class constexpr const_cast decltype delete dynamic_cast explicit export "
    "friend mutable namespace new noexcept nullptr operator override final private protected public "
    "reinterpret_cast static_assert static_cast template this throw try typeid typename using virtual"
)
_JAVA_KEYWORDS = (
    "abstract assert boolean break byte case catch char class const continue default do double else "
    "enum extends final finally float for goto if implements import instanceof int interface long native "
    "new package private protected public return short static strictfp super switch synchronized this "
    "throw throws transient try void volatile while var record yield sealed permits true false null"
)


class CFamilySyntaxHighlighter(QSyntaxHighlighter):
    """Highlighting for Java, C and C++: keywords, strings, numbers, // and /* */ comments."""

    def __init__(self, document, language: str = "c"):
        super().__init__(document)
        words = {"java": _JAVA_KEYWORDS, "cpp": _CPP_KEYWORDS}.get(language, _C_KEYWORDS).split()

        def fmt(color, bold=False, italic=False):
            f = QTextCharFormat()
            f.setForeground(QColor(color))
            if bold:
                f.setFontWeight(QFont.Weight.Bold)
            f.setFontItalic(italic)
            return f

        self.rules = [
            (re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*(?=\s*\()"), fmt(theme.ACCENT)),
            (re.compile(r"\b(" + "|".join(map(re.escape, words)) + r")\b"), fmt(theme.PURPLE, bold=True)),
            (re.compile(r"\b(0[xX][0-9a-fA-F]+|[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?)[uUlLfF]*\b"), fmt(theme.ORANGE)),
        ]
        if language == "java":
            self.rules.append((re.compile(r"@[A-Za-z_][A-Za-z0-9_.]*"), fmt(theme.TEAL)))
        else:
            self.rules.append((re.compile(r"^\s*#\s*[a-z]+[^\n]*"), fmt(theme.TEAL)))
        self.string_fmt = fmt(theme.SUCCESS)
        self.string_re = re.compile(r'"(\\.|[^"\\])*"|\'(\\.|[^\'\\])*\'')
        self.comment_fmt = fmt(theme.TEXT_FAINT, italic=True)

    def highlightBlock(self, text):
        for pattern, f in self.rules:
            for m in pattern.finditer(text):
                self.setFormat(m.start(), m.end() - m.start(), f)
        for m in self.string_re.finditer(text):
            self.setFormat(m.start(), m.end() - m.start(), self.string_fmt)

        # Comments last so they win; /* */ may span lines (block state 1).
        self.setCurrentBlockState(0)
        i = 0
        in_block = self.previousBlockState() == 1
        start = 0
        while i < len(text):
            if in_block:
                end = text.find("*/", i)
                if end == -1:
                    self.setFormat(start, len(text) - start, self.comment_fmt)
                    self.setCurrentBlockState(1)
                    return
                self.setFormat(start, end + 2 - start, self.comment_fmt)
                in_block, i = False, end + 2
                continue
            string = self.string_re.match(text, i)
            if string:
                i = string.end()
                continue
            if text.startswith("//", i):
                self.setFormat(i, len(text) - i, self.comment_fmt)
                return
            if text.startswith("/*", i):
                in_block, start, i = True, i, i + 2
                continue
            i += 1


def make_code_highlighter(document, language: str = "python"):
    """Highlighter for a code document in the given language key."""
    if language in ("java", "c", "cpp"):
        return CFamilySyntaxHighlighter(document, language)
    return PythonSyntaxHighlighter(document)
