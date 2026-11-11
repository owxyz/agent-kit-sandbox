import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import yamlite  # noqa: E402


class LoadTests(unittest.TestCase):
    def test_on_key_stays_a_string(self):
        self.assertEqual(yamlite.load("on: push\n"), {"on": "push"})

    def test_scalars(self):
        doc = yamlite.load("a: true\nb: 3\nc: 2026-01-02\nd: ~\ne: 'it''s'\nf: \"x\\ty\"\n")
        self.assertEqual(doc, {"a": True, "b": 3, "c": "2026-01-02", "d": None, "e": "it's", "f": "x\ty"})

    def test_sequence_at_parent_indent(self):
        self.assertEqual(yamlite.load("a:\n- 1\n- x: 2\n  y: 3\nb: 4\n"),
                         {"a": [1, {"x": 2, "y": 3}], "b": 4})

    def test_flow_collections_with_expressions(self):
        doc = yamlite.load("a: [x, ${{ matrix.y }}, 'z, w']\nb: {c: ${{ d }}, e: [1, 2]}\n")
        self.assertEqual(doc, {"a": ["x", "${{ matrix.y }}", "z, w"], "b": {"c": "${{ d }}", "e": [1, 2]}})

    def test_multiline_flow(self):
        self.assertEqual(yamlite.load("a: [\n  1, # one\n  2\n]\n"), {"a": [1, 2]})

    def test_block_scalars(self):
        doc = yamlite.load("a: |\n  one\n    two\n\n  three\nb: >-\n  x\n  y\nc: 1\n")
        self.assertEqual(doc, {"a": "one\n  two\n\nthree\n", "b": "x y", "c": 1})

    def test_block_scalar_in_sequence_item(self):
        doc = yamlite.load("s:\n  - run: |\n      a\n      b\n    env: {X: 1}\n")
        self.assertEqual(doc, {"s": [{"run": "a\nb\n", "env": {"X": 1}}]})

    def test_comments(self):
        doc = yamlite.load("# top\n---\na: b # note\nc: 'd # kept'\ne: f#kept\n")
        self.assertEqual(doc, {"a": "b", "c": "d # kept", "e": "f#kept"})

    def test_multiline_plain(self):
        self.assertEqual(yamlite.load("if: a &&\n  b\nx: 1\n"), {"if": "a && b", "x": 1})

    def test_anchor_and_alias(self):
        doc = yamlite.load("a: &base\n  - 1\nb: *base\n")
        self.assertEqual(doc, {"a": [1], "b": [1]})

    def test_colon_inside_url_is_not_a_key(self):
        self.assertEqual(yamlite.load("- http://x.y/z\n"), ["http://x.y/z"])

    def test_rejected_input(self):
        for text in ("a:\n\tb: 1\n", "a: 1\na: 2\n", "a: [1, 2\n", "a: 'x\n", "a: !!str x\n",
                     "<<: {a: 1}\n", "a: 1\n---\nb: 2\n", "a: b\n  c: d\n", "a: *missing\n",
                     "a:\n    b: 1\n  c: 2\n"):
            with self.assertRaises(yamlite.YamlError, msg=repr(text)):
                yamlite.load(text)

    def test_error_does_not_repeat_line_content(self):
        with self.assertRaises(yamlite.YamlError) as caught:
            yamlite.load("a: SENSITIVE_TEXT\n  b: SENSITIVE_TEXT\n")
        self.assertNotIn("SENSITIVE_TEXT", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
