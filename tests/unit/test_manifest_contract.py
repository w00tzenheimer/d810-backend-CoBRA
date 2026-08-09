"""The contract d810 relies on, checked from this side of the boundary.

These moved out of d810's ``tests/unit/core/test_plugins.py`` when the backend
was extracted. d810 keeps the *generic* protocol tests (a probe that returns a
reason marks the backend unavailable, and so on) against fake backends; what
belongs here is whether THIS package satisfies that protocol.

Deliberately no import of ``d810.core.plugins``: the manifest must stay
readable by a d810 that predates the plugin protocol, so these assertions
describe its shape directly rather than round-tripping it through d810's
coercion.
"""

from __future__ import annotations

import importlib
import unittest

import d810_cobra as pkg


class TestManifestShape(unittest.TestCase):
    def test_declares_the_three_required_fields(self):
        for key in ("name", "api_version", "provides"):
            self.assertIn(key, pkg.MANIFEST)

    def test_name_matches_the_entry_point(self):
        """pyproject registers `cobra = ...`; a mismatch here is invisible."""
        self.assertEqual(pkg.MANIFEST["name"], "cobra")

    def test_api_version_is_an_int(self):
        self.assertIsInstance(pkg.MANIFEST["api_version"], int)

    def test_provides_is_a_string_so_d810_resolves_it_lazily(self):
        """A callable would be resolved eagerly during discovery.

        The point of the string form is that an incompatible d810 rejects this
        backend after reading three fields, without importing solve.py and
        therefore without loading the compiled extension.
        """
        self.assertIsInstance(pkg.MANIFEST["provides"], str)

    def test_declares_its_rule_module(self):
        """Without this, CobraSolveRule never registers.

        d810 scans ``d810.optimizers.__path__`` for rules, which cannot reach a
        module inside this package -- the backend would report available while
        mba-solve was silently absent.
        """
        self.assertIn("d810_cobra.rules.cobra_solve", pkg.MANIFEST["rules"])

    def test_rules_is_a_sequence_not_a_bare_string(self):
        """A bare string would iterate per-character into meaningless imports."""
        self.assertNotIsInstance(pkg.MANIFEST["rules"], str)


class TestProbeHook(unittest.TestCase):
    """``provides`` must resolve to a module carrying the probe hook."""

    def setUp(self):
        self.solve = importlib.import_module(pkg.MANIFEST["provides"])

    def test_probe_hook_is_callable(self):
        self.assertTrue(callable(getattr(self.solve, "d810_backend_probe", None)))

    def test_probe_agrees_with_the_module_flag(self):
        reason = self.solve.d810_backend_probe()
        if self.solve.binding_available():
            self.assertIsNone(reason)
        else:
            self.assertIsNotNone(reason)

    def test_an_absent_binding_names_the_missing_piece(self):
        """"unavailable" with no reason is the failure the protocol exists to kill.

        Forced rather than left to whether the machine running the suite
        happens to have built the extension.
        """
        from unittest import mock

        with mock.patch.object(self.solve, "_BINDING_AVAILABLE", False), mock.patch.object(
            self.solve, "_BINDING_ERROR", "No module named 'd810_cobra._cobra'"
        ):
            reason = self.solve.d810_backend_probe()

        self.assertIsNotNone(reason)
        self.assertIn("_cobra", reason)


if __name__ == "__main__":
    unittest.main()
