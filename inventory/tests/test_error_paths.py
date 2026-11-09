"""Each rejected input must fail for its own stated reason."""
import contextlib
import io
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import scan_workflows as scanner  # noqa: E402
import schemalite  # noqa: E402
import validate  # noqa: E402
import yamlite  # noqa: E402


def write(root, relative, content):
    path = os.path.join(root, relative)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(content)


class YamlReasonTests(unittest.TestCase):
    def test_each_rejection_reports_its_reason(self):
        cases = [
            ('a: "\\xZZ"\n', "invalid escape"),
            ('a: "\\q"\n', "invalid escape"),
            ("? a\n", "complex mapping keys"),
            ("&anchor key: 1\n", "on keys are not supported"),
            ("a: [1] x\n", "unexpected content after flow"),
            ("a: [*b]\n", "in flow collections are not supported"),
            ("a: [[1] 2]\n", "expected ',' or ']'"),
            ("a: {b: 1, b: 2}\n", "duplicate key in flow"),
            ("a: {b: [1] c}\n", "expected ',' or '}'"),
            ("%YAML 1.2\na: 1\n", "directives are not supported"),
            ("- a\n---\n- b\n", "multiple YAML documents"),
            ("a: 1\n- b\n", "sequence item where a mapping key"),
            ("a: 'x' y\n", "unexpected content after quoted"),
            ("a: b: c\n", "plain value cannot contain"),
        ]
        for text, reason in cases:
            with self.subTest(text=text):
                with self.assertRaises(yamlite.YamlError) as caught:
                    yamlite.load(text)
                self.assertIn(reason, caught.exception.reason)

    def test_flow_values_continue_across_lines(self):
        self.assertEqual(yamlite.load("a: ['x\n  y']\n"), {"a": ["x y"]})
        self.assertEqual(yamlite.load("a: [${{ x\n  }}]\n"), {"a": ["${{ x }}"]})


class SchemaReasonTests(unittest.TestCase):
    def test_unknown_type_is_refused(self):
        with self.assertRaisesRegex(schemalite.SchemaError, "unsupported type"):
            schemalite.validate(1, {"type": "weird"})

    def test_remote_ref_is_refused(self):
        with self.assertRaisesRegex(schemalite.SchemaError, "only local"):
            schemalite.validate(1, {"$ref": "https://example.test/schema"})


class CliReasonTests(unittest.TestCase):
    def assert_usage_error(self, main, argv, text):
        err = io.StringIO()
        with self.assertRaises(SystemExit) as caught, contextlib.redirect_stderr(err):
            main(argv)
        self.assertEqual(caught.exception.code, 2)
        self.assertIn(text, err.getvalue())

    def test_validate_rejects_bad_today(self):
        self.assert_usage_error(validate.main, ["register", "--today", "soon"], "--today must be")

    def test_scanner_rejects_bad_pattern(self):
        with tempfile.TemporaryDirectory() as root:
            self.assert_usage_error(scanner.main, [root, "--agent-pattern", "("], "invalid --agent-pattern")


class ScannerFileTests(unittest.TestCase):
    def only_workflow(self, root):
        return scanner.scan(root)["repos"][0]["workflows"][0]

    def test_non_utf8_workflow_is_reported(self):
        with tempfile.TemporaryDirectory() as root:
            write(root, "r/.github/workflows/w.yml", b"name: \xff\xfe\n")
            workflow = self.only_workflow(root)
        self.assertFalse(workflow["parsed"])
        self.assertIn("UTF-8", workflow["flags"][0]["detail"])

    def test_workflow_that_is_not_a_mapping_is_reported(self):
        with tempfile.TemporaryDirectory() as root:
            write(root, "r/.github/workflows/w.yml", b"- a\n- b\n")
            workflow = self.only_workflow(root)
        self.assertFalse(workflow["parsed"])
        self.assertIn("not a mapping", workflow["flags"][0]["detail"])

    def test_invalid_local_action_adds_no_agent_label(self):
        with tempfile.TemporaryDirectory() as root:
            write(root, "r/.github/actions/x/action.yml", b"a: 1\n  b: 2\n")
            write(root, "r/.github/workflows/w.yml",
                  b"on: push\npermissions: {}\njobs:\n  a:\n    runs-on: x\n    steps:\n"
                  b"      - uses: ./.github/actions/x\n")
            workflow = self.only_workflow(root)
        self.assertTrue(workflow["parsed"])
        self.assertFalse(workflow["is_agent"])


if __name__ == "__main__":
    unittest.main()
