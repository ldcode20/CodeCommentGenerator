"""
Value-precision tests: constant folding, infeasible branches and container shapes.

Each "safe" case is dangerous under a union-of-everything taint model and must not be
reported; each "vulnerable" twin differs only in the value that reaches the sink.
"""
import textwrap
import unittest

from src.security import analyze_source

PRE = "import os\nfrom flask import request\n"


def rules(body: str):
    rep = analyze_source(PRE + textwrap.dedent(body), "t.py")
    return sorted(f.rule_id for f in rep.active())


class TestConstantBranches(unittest.TestCase):

    def test_constant_if_prunes_tainted_branch(self):
        safe = """
            def f():
                param = request.args["p"]
                num = 86
                if 7 * 42 - num > 200:
                    bar = "fixed"
                else:
                    bar = param
                os.system("echo " + bar)
        """
        self.assertEqual(rules(safe), [])
        self.assertEqual(rules(safe.replace("num = 86", "num = 106")), ["SEC002"])

    def test_constant_ifexp(self):
        self.assertEqual(rules("""
            def f():
                param = request.args["p"]
                num = 106
                bar = "fixed" if 7 * 18 + num > 200 else param
                os.system("echo " + bar)
        """), [])

    def test_unknown_condition_keeps_both_branches(self):
        self.assertEqual(rules("""
            def f(flag):
                param = request.args["p"]
                bar = "fixed" if flag else param
                os.system("echo " + bar)
        """), ["SEC002"])

    def test_constant_string_membership(self):
        body = """
            def f():
                param = request.args["p"]
                test = "This should never happen"
                if 'should' not in test:
                    bar = "x"
                else:
                    bar = param
                os.system("echo " + bar)
        """
        self.assertEqual(rules(body), ["SEC002"])            # else branch is the one taken
        self.assertEqual(rules(body.replace("'should' not in", "'should' in")), [])

    def test_match_on_constant_subject(self):
        body = """
            def f():
                param = request.args["p"]
                possible = "ABC"
                guess = possible[{i}]
                match guess:
                    case 'A':
                        bar = param
                    case 'B':
                        bar = 'bob'
                    case _:
                        bar = 'other'
                os.system("echo " + bar)
        """
        self.assertEqual(rules(body.format(i=0)), ["SEC002"])
        self.assertEqual(rules(body.format(i=1)), [])

    def test_loop_counter_is_not_constant(self):
        self.assertEqual(rules("""
            def f():
                param = request.args["p"]
                i = 0
                bar = "safe"
                while i < 3:
                    if i == 2:
                        bar = param
                    i = i + 1
                os.system("echo " + bar)
        """), ["SEC002"])


class TestContainerShapes(unittest.TestCase):

    def test_dict_constant_keys(self):
        body = """
            def f():
                param = request.args["p"]
                m = {}
                m['keyA'] = 'a-Value'
                m['keyB'] = param
                bar = m['{key}']
                os.system("echo " + bar)
        """
        self.assertEqual(rules(body.replace("{key}", "keyA")), [])
        self.assertEqual(rules(body.replace("{key}", "keyB")), ["SEC002"])

    def test_list_append_pop_index(self):
        body = """
            def f():
                param = request.args["p"]
                lst = []
                lst.append('safe')
                lst.append(param)
                lst.append('moresafe')
                lst.pop(0)
                bar = lst[{i}]
                os.system("echo " + bar)
        """
        self.assertEqual(rules(body.format(i=0)), ["SEC002"])   # param moved to index 0
        self.assertEqual(rules(body.format(i=1)), [])

    def test_alias_drops_precision(self):
        self.assertEqual(rules("""
            def f():
                param = request.args["p"]
                a = ['safe']
                b = a
                b.append(param)
                os.system("echo " + a[-1])
        """), ["SEC002"])

    def test_container_passed_to_unknown_call(self):
        """Shape is dropped either way; argument mutation is only assumed when opted in."""
        from src.security.rules import Registry
        src = PRE + textwrap.dedent("""
            from lib import fill
            def f():
                param = request.args["p"]
                m = {'k': 'safe'}
                fill(m, param)
                os.system("echo " + m['k'])
        """)
        default = [f.rule_id for f in analyze_source(src, "t.py").active()]
        opted = [f.rule_id for f in analyze_source(src, "t.py",
                                                   Registry(unknown_calls_mutate_args=True)).active()]
        self.assertEqual(default, [])
        self.assertEqual(opted, ["SEC002"])

    def test_branch_join_of_shapes(self):
        self.assertEqual(rules("""
            def f(flag):
                param = request.args["p"]
                m = {'a': 'x', 'b': 'y'}
                if flag:
                    m['a'] = param
                os.system("echo " + m['b'])
                os.system("echo " + m['a'])
        """), ["SEC002"])


class TestObjectAliasing(unittest.TestCase):

    def test_two_aliases_of_one_object(self):
        self.assertEqual(rules("""
            class Box:
                pass
            def f():
                a = Box()
                b = a
                b.cmd = request.args["c"]
                os.system(a.cmd)
        """), ["SEC002"])

    def test_independent_objects_same_field_name(self):
        self.assertEqual(rules("""
            class Box:
                pass
            def f():
                a = Box()
                b = Box()
                b.cmd = request.args["c"]
                a.cmd = "uptime"
                os.system(a.cmd)
        """), [])

    def test_field_overwritten_before_use(self):
        self.assertEqual(rules("""
            class Box:
                pass
            def f():
                a = Box()
                a.cmd = request.args["c"]
                a.cmd = "uptime"
                os.system(a.cmd)
        """), [])

    def test_field_sanitized_before_sink(self):
        body = """
            import shlex
            class Box:
                pass
            def f():
                a = Box()
                a.cmd = request.args["c"]
                {line}
                os.system("echo " + a.cmd)
        """
        self.assertEqual(rules(body.format(line="a.cmd = shlex.quote(a.cmd)")), [])
        self.assertEqual(rules(body.format(line="a.cmd = a.cmd.strip()")), ["SEC002"])

    def test_rebinding_breaks_alias(self):
        self.assertEqual(rules("""
            def f():
                a = []
                b = a
                b = []
                b.append(request.args["c"])
                os.system("echo " + " ".join(a))
        """), [])


class TestResponseTuple(unittest.TestCase):

    def test_header_value_is_not_html_body(self):
        body = """
            from flask import make_response
            def f():
                bar = request.form["b"]
                return make_response(({body}, {{'X-Custom': {hdr}}}))
        """
        self.assertEqual(rules(body.format(body="'static text'", hdr="bar")), [])
        self.assertEqual(rules(body.format(body="'<p>' + bar", hdr="'x'")), ["SEC014"])


class TestTryFinally(unittest.TestCase):

    def test_sink_in_finally_reached_by_return_path_reported_once(self):
        found = analyze_source(PRE + textwrap.dedent("""
            def f():
                cmd = request.args["c"]
                try:
                    return 1
                finally:
                    os.system(cmd)
        """), "t.py").active()
        self.assertEqual([(x.rule_id, x.line) for x in found], [("SEC002", 9)])

    def test_sanitiser_in_finally_applies_before_return(self):
        self.assertEqual(rules("""
            import shlex
            def f():
                v = request.args["c"]
                try:
                    if not v:
                        return None
                finally:
                    v = shlex.quote(v)
                os.system("echo " + v)
        """), [])


class TestCallableResolution(unittest.TestCase):

    def test_bound_method_alias(self):
        self.assertEqual(rules("""
            import sqlite3
            def f():
                run = sqlite3.connect("d").cursor().execute
                run("SELECT * FROM t WHERE q = '" + request.args["q"] + "'")
        """), ["SEC005"])

    def test_function_alias_and_partial(self):
        self.assertEqual(rules("""
            import functools
            def f():
                sh = os.system
                sh(request.args["a"])
                p = functools.partial(os.system)
                p(request.args["b"])
        """), ["SEC002", "SEC002"])

    def test_getattr_literal_vs_computed(self):
        self.assertEqual(rules("""
            def f():
                getattr(os, "system")(request.args["c"])
        """), ["SEC002"])
        self.assertEqual(rules("""
            def f(name):
                getattr(os, name)(request.args["c"])
        """), [])          # computed attribute: unresolved (documented limitation)

    def test_alias_of_safe_function_is_safe(self):
        self.assertEqual(rules("""
            import shlex
            def f():
                q = shlex.quote
                os.system("echo " + q(request.args["c"]))
        """), [])

    def test_alias_of_project_function(self):
        self.assertEqual(rules("""
            def helper(x):
                os.system(x)
            def f():
                h = helper
                h(request.args["c"])
        """), ["SEC002"])

    def test_alias_merge_and_slices_regression(self):
        """Regression: callable descriptors crashed at CFG joins; x[1:] was folded as x[:1]."""
        src = PRE + textwrap.dedent("""
            def f(flag):
                g = os.system
                if flag:
                    g = print
                g("ls")
                tail = 'abcdef'[1:]
                if tail == 'bcdef':
                    os.system(request.args["c"])
                whole = 'abc'[:]
                return whole
        """)
        rep = analyze_source(src, "t.py")
        self.assertIsNone(rep.parse_error)
        self.assertEqual([(f.rule_id, f.line) for f in rep.active()], [("SEC002", 11)])

    def test_rebound_alias_uses_latest_target(self):
        self.assertEqual(rules("""
            import shlex
            def f():
                g = os.system
                g = print
                g(request.args["c"])
        """), [])


class TestRegistryAdditions(unittest.TestCase):

    def test_weak_random_into_session_or_cookie(self):
        body = """
            import random, secrets
            from flask import make_response
            session = {{}}
            def f():
                value = str({gen})
                session['remember'] = value
                resp = make_response("ok")
                resp.set_cookie('remember', value)
                return resp
        """
        self.assertEqual(rules(body.format(gen="random.getrandbits(32)")), ["SEC011", "SEC011"])
        self.assertEqual(rules(body.format(gen="secrets.randbits(32)")), [])
        self.assertEqual(rules(body.format(gen="random.SystemRandom().getrandbits(32)")), [])

    def test_random_without_security_use_is_quiet(self):
        self.assertEqual(rules("""
            import random
            def shuffle_deck(deck):
                random.shuffle(deck)
                return deck[random.randint(0, 3)]
        """), [])

    def test_untrusted_data_into_session_is_not_weak_randomness(self):
        self.assertEqual(rules("""
            session = {}
            def f():
                session['name'] = request.args["n"]
        """), [])

    def test_path_existence_probe(self):
        found = analyze_source(PRE + textwrap.dedent("""
            def f():
                p = "/srv/files/" + request.args["f"]
                return os.path.exists(p)
        """), "t.py").active()
        self.assertEqual([(x.rule_id, x.severity) for x in found], [("SEC013", "medium")])

    def test_configparser_style_set_get(self):
        self.assertEqual(rules("""
            import configparser
            def f():
                conf = configparser.ConfigParser()
                conf.add_section('s')
                conf.set('s', 'k', request.args["p"])
                os.system("echo " + conf.get('s', 'k'))
        """), ["SEC002"])

    def test_configparser_reads_by_constant_key(self):
        body = """
            import configparser
            def f():
                conf = configparser.ConfigParser()
                conf.add_section('s')
                conf.set('s', 'keyA', 'a_Value')
                conf.set('s', 'keyB', request.args["p"])
                os.system("echo " + conf.get('s', '{key}'))
        """
        self.assertEqual(rules(body.replace("{key}", "keyA")), [])
        self.assertEqual(rules(body.replace("{key}", "keyB")), ["SEC002"])

    def test_str_of_resolved_path_prefix_check(self):
        body = """
            import pathlib
            BASE = pathlib.Path("/srv/files")
            def f():
                p = (BASE / request.args["f"]){resolve}
                if not str(p).startswith(str(BASE)):
                    return "bad"
                return p.read_text()
        """
        self.assertEqual(rules(body.replace("{resolve}", ".resolve()")), [])
        self.assertEqual(rules(body.replace("{resolve}", "")), ["SEC013"])

    def test_dotdot_substring_check_lowers_confidence_only(self):
        found = analyze_source(PRE + textwrap.dedent("""
            def f():
                name = request.args["f"]
                if '../' in name:
                    return "bad"
                return open("/srv/files/" + name).read()
        """), "t.py").active()
        self.assertEqual([(x.rule_id, x.status, x.confidence) for x in found],
                         [("SEC013", "potential", "medium")])
        self.assertTrue(any("'..' substring check" in r for r in found[0].confidence_reasons))


if __name__ == "__main__":
    unittest.main(verbosity=2)
