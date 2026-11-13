"""Tests for the bug and quality rules (BUG/QLT) and syntax errors."""
from reviewbot import review_source


def rules(findings):
    return {f.rule for f in findings}


def test_syntax_error_is_critical():
    findings = review_source("def broken(:\n")
    assert "BUG000" in rules(findings)
    assert findings[0].severity == "critical"


def test_mutable_default_argument():
    assert "BUG001" in rules(review_source("def f(items=[]):\n    return items\n"))


def test_bare_except():
    assert "BUG002" in rules(review_source("try:\n    risky()\nexcept:\n    log()\n"))


def test_silent_except_pass():
    src = "try:\n    risky()\nexcept ValueError:\n    pass\n"
    assert "BUG003" in rules(review_source(src))


def test_comparison_with_none():
    assert "BUG004" in rules(review_source("if x == None:\n    pass\n"))
    assert "BUG004" not in rules(review_source("if x is None:\n    pass\n"))


def test_identity_check_with_literal():
    assert "BUG005" in rules(review_source("if x is 1:\n    pass\n"))
    assert "BUG005" not in rules(review_source("if x == 1:\n    pass\n"))


def test_unreachable_code():
    src = "def f():\n    return 1\n    print('dead')\n"
    assert "BUG006" in rules(review_source(src))


def test_unused_import():
    assert "BUG007" in rules(review_source("import json\nx = 1\n"))


def test_unused_variable():
    src = "def f():\n    temp = 42\n    return 1\n"
    assert "BUG008" in rules(review_source(src))


def test_used_variable_is_clean():
    src = "def f():\n    temp = 42\n    return temp\n"
    assert "BUG008" not in rules(review_source(src))


def test_assert_flagged():
    assert "BUG010" in rules(review_source("def f(x):\n    assert x > 0\n    return x\n"))


def test_function_too_long():
    body = "\n".join(f"    x{i} = {i}" for i in range(55))
    src = f"def f():\n{body}\n    return 1\n"
    assert "QLT001" in rules(review_source(src))


def test_too_many_parameters():
    assert "QLT002" in rules(review_source("def f(a, b, c, d, e, f):\n    pass\n"))


def test_deep_nesting():
    src = ("def f(a, b, c, d, e, g):\n"
           "    if a:\n        if b:\n            if c:\n                if d:\n"
           "                    if e:\n                        if g:\n"
           "                            return 1\n    return 0\n")
    assert "QLT003" in rules(review_source(src))


def test_high_complexity():
    branches = "\n".join(f"    if x == {i}:\n        y += {i}" for i in range(12))
    src = f"def f(x):\n    y = 0\n{branches}\n    return y\n"
    assert "QLT004" in rules(review_source(src))


def test_long_line_and_todo():
    long_line = "x = " + "1 + " * 60 + "1\n"
    assert "QLT005" in rules(review_source(long_line))
    assert "QLT006" in rules(review_source("# TODO: fix this later\nx = 1\n"))


def test_print_flagged():
    assert "QLT007" in rules(review_source("print('hello')\n"))


def test_duplicated_function_body():
    src = ("def a():\n    x = 1\n    y = 2\n    return x + y\n\n"
           "def b():\n    x = 1\n    y = 2\n    return x + y\n")
    assert "QLT008" in rules(review_source(src))


def test_clean_function_is_clean():
    src = ("def add(a, b):\n    \"\"\"Add two numbers.\"\"\"\n    return a + b\n")
    assert review_source(src) == []
