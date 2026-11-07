"""Compatibility and copy-drift guards; no Docker required."""

import ast
import shutil
import subprocess
import unittest
from pathlib import Path

from proveit import config, poc, sandbox, targets

ROOT = Path(__file__).resolve().parent.parent


class PyYAMLCompatibility(unittest.TestCase):
    def test_pinned_harness_hash(self):
        self.assertEqual(sandbox.harness_digest(targets.PYYAML), "9b1b9e654cc0f147")

    def test_adapter_delegates_to_legacy_values(self):
        t = targets.PYYAML
        self.assertIs(t.builds, config.TARGET["builds"])
        self.assertIs(t.entry_points, config.ENTRY_POINTS)
        self.assertEqual(t.out_of_scope_names, poc.OUT_OF_SCOPE_NAMES)
        self.assertEqual(t.poc_format_help, config.POC_FORMAT_HELP)

    def test_legacy_and_unknown_records_use_documented_default(self):
        for record in ({}, {"target": ""}, {"target": "nope"}):
            self.assertIs(targets.for_record(record), targets.PYYAML)

    @unittest.skipUnless(shutil.which("git"), "Git is unavailable")
    def test_target_directory_unchanged_since_adapter_base(self):
        args = ["git", "-c", "safe.directory=" + str(ROOT), "-C", str(ROOT)]
        probe = subprocess.run(args + ["rev-parse", "--verify", "c78f1ff^{commit}"],
                               capture_output=True, text=True, timeout=15)
        if probe.returncode:
            self.skipTest("adapter base c78f1ff is unavailable (source archive or shallow checkout)")
        diff = subprocess.run(args + ["diff", "c78f1ff", "--", "target/"],
                              capture_output=True, text=True, timeout=15)
        self.assertEqual(diff.returncode, 0, diff.stderr)
        self.assertEqual(diff.stdout, "")


def tree(folder, name):
    return ast.parse((ROOT / folder / name).read_text(encoding="utf-8"))


class LibraryNormalization(ast.NodeTransformer):
    """Only the documented library import/name and child call table may differ."""
    def visit_Name(self, node):
        if node.id in ("sqlparse", "_lib"):
            node.id = "yaml"
        return node

    def visit_Constant(self, node):
        if node.value in ("sqlparse", "sqlparse."):
            node.value = str(node.value).replace("sqlparse", "yaml")
        return node

    def visit_Import(self, node):
        for alias in node.names:
            if alias.name == "sqlparse":
                alias.name, alias.asname = "yaml", None
        return node

    def visit_Assign(self, node):
        if any(isinstance(t, ast.Name) and t.id == "call" for t in node.targets):
            node.value = ast.Constant(value="target-specific allowlisted call table")
        return self.generic_visit(node)


class HarnessDrift(unittest.TestCase):
    def test_shared_constants_match(self):
        def constants(folder):
            return {n.targets[0].id: ast.dump(n.value) for n in tree(folder, "harness.py").body
                    if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)
                    and n.targets[0].id != "ENTRY_POINTS"}
        self.assertEqual(constants("target"), constants("target-sqlparse"))

    def test_every_shared_function_matches_except_documented_library_values(self):
        for name in ("harness.py", "child.py"):
            def functions(folder):
                t = LibraryNormalization().visit(tree(folder, name))
                return {n.name: ast.dump(n, include_attributes=False) for n in t.body
                        if isinstance(n, ast.FunctionDef)}
            self.assertEqual(functions("target"), functions("target-sqlparse"), name)

    def test_classification_and_child_limits_are_identical_without_normalization(self):
        for fn in ("classify", "limit_child"):
            def get(folder):
                return ast.dump(next(n for n in tree(folder, "harness.py").body
                                     if isinstance(n, ast.FunctionDef) and n.name == fn))
            self.assertEqual(get("target"), get("target-sqlparse"), fn)

    def test_copied_child_allowlist_matches_its_adapter(self):
        t = tree("target-sqlparse", "child.py")
        entry = next(n.value for n in t.body if isinstance(n, ast.Assign)
                     and any(isinstance(x, ast.Name) and x.id == "ENTRY_POINTS" for x in n.targets))
        self.assertEqual(set(ast.literal_eval(entry)), set(targets.SQLPARSE.entry_points))
