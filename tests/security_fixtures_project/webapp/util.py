"""Pure helpers used across modules."""
import shlex


def normalize(value):
    return value.strip().lower()


def to_int(value):
    return int(value)


def quote_for_shell(value):
    return shlex.quote(value)


def build_where(column, value):
    return column + " = '" + value + "'"
