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
