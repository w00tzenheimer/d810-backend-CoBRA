"""Proof-layer tests: the inline budget and the meaning of a timeout.

The critical property here is that a *short* budget degrades to UNKNOWN and
never to REFUTED.  The rule treats UNKNOWN as "skip this rewrite", so a tight
inline timeout costs coverage only.  If a timeout could ever surface as
REFUTED, shortening the budget would start discarding valid rewrites and --
worse -- would log them as if CoBRA had produced bad math.
"""

from __future__ import annotations

import unittest

from d810_cobra.prove import (
    DEFAULT_TIMEOUT_MS,
    INLINE_TIMEOUT_MS,
    ProofResult,
    proof_gate_status,
    prove_equivalent,
    reset_z3_detection,
    z3_available,
)

V = lambda n: {"kind": "var", "name": n}  # noqa: E731
C = lambda v: {"kind": "const", "value": v}  # noqa: E731
B = lambda o, a, b: {"kind": "bin", "op": o, "a": a, "b": b}  # noqa: E731


class TestInlineBudget(unittest.TestCase):
    def test_inline_budget_is_far_below_the_escalation_budget(self):
        """The two budgets serve different masters and must not converge.

        INLINE_TIMEOUT_MS bounds the critical path; DEFAULT_TIMEOUT_MS is what
        the off-path prover may spend.  Measured on VM_DecryptPacket, 98% of
        total proof time sat in 4 of 14 proofs, so the split is the whole
        point of the design.
        """
        self.assertLess(INLINE_TIMEOUT_MS, DEFAULT_TIMEOUT_MS)

    def test_inline_budget_matches_the_measured_knee(self):
        """1500ms was chosen from data, not taste, on two functions.

        VM_DecryptPacket, sorted proof times (ms) over 14 accepted candidates:
        0 1 3 8 115 197 284 440 701 1611 6213 18554 68113 93610.
        500ms keeps 8/14 for 4.05s; 1000ms buys one more for +2.7s; 2000ms
        buys two more for +7.3s.

        sub_7FF85A852A00, 13 accepted candidates, timeout swept:
            500ms ->  7 proved,  6 starved,  3.62s
           1500ms ->  9 proved,  4 starved,  8.32s
           4000ms ->  9 proved,  4 starved, 20.75s
        The gain SATURATES at 1500ms: 4000ms buys nothing for 2.5x the time,
        so the remaining 4 are genuinely hard rather than clipped.  Both
        datasets agree that ~1500ms buys about two proofs for about +5s.

        Raising it costs first-pass latency only.  A starved proof is not
        lost: it escalates to DEFAULT_TIMEOUT_MS off the critical path, lands
        in the rewrite table, and is flushed to the durable proof cache, so a
        later decompile applies it as a table hit with no inline proof at all.
        """
        self.assertEqual(INLINE_TIMEOUT_MS, 1500)

    def test_inline_budget_stays_below_the_saturation_point(self):
        """Past 1500ms the sweep bought zero extra proofs for 2.5x the time."""
        self.assertLessEqual(INLINE_TIMEOUT_MS, 1500)


class TestLazyZ3Resolution(unittest.TestCase):
    """Availability must reflect sys.path at USE time, not at import time.

    z3 is not on sys.path when the interpreter starts inside IDA.  d810 puts it
    there: importing d810 runs ensure_speedups_on_path(), which prepends
    ~/.d810-speedups and pins the native libz3 via builtins.Z3_LIB_DIRS.

    Snapshotting `import z3` at module scope therefore made the answer depend on
    whether d810 had been imported first.  Import this module too early and
    availability was pinned False for the life of the process; with
    require_proof=True that skips every candidate and applies nothing, which is
    indistinguishable from "the solver matched nothing" (d81-ni1k).

    It also makes installing z3 at runtime pointless -- the answer could never
    change without restarting IDA, which is what the opt-in installer needs.
    """

    def setUp(self):
        reset_z3_detection()
        self.addCleanup(reset_z3_detection)

    def test_availability_is_recomputed_after_a_reset(self):
        """A reset must actually re-probe rather than serve a stale answer."""
        seen = []

        def probe():
            seen.append(1)
            return True

        self.assertTrue(z3_available(_probe=probe))
        self.assertEqual(len(seen), 1)

    def test_result_is_cached_so_the_hot_path_does_not_re_import(self):
        """check_and_replace runs per instruction; probing each time is waste."""
        calls = []

        def probe():
            calls.append(1)
            return True

        z3_available(_probe=probe)
        z3_available(_probe=probe)
        z3_available(_probe=probe)
        self.assertEqual(len(calls), 1)

    def test_a_negative_result_is_not_cached_forever(self):
        """The installer's whole point is that 'absent' can become 'present'."""
        answers = iter([False, True])
        probe = lambda: next(answers)  # noqa: E731

        self.assertFalse(z3_available(_probe=probe))
        reset_z3_detection()
        self.assertTrue(z3_available(_probe=probe))

    def test_import_order_no_longer_decides_the_answer(self):
        """The regression: prove imported before d810 pinned this False."""
        self.assertFalse(z3_available(_probe=lambda: False))
        reset_z3_detection()
        self.assertTrue(z3_available(_probe=lambda: True))

    def test_a_d810_side_install_invalidates_the_cached_answer(self):
        """An install during the session must not need an IDA restart.

        d810 bumps a generation counter when optional-dependency availability
        may have changed. Keying the cache on it means any backend self-heals
        without d810 having to know this package exists.
        """
        from d810.speedups.bootstrap import invalidate_optional_dependency_cache

        answers = iter([False, True])
        probe = lambda: next(answers)  # noqa: E731

        self.assertFalse(z3_available(_probe=probe))
        invalidate_optional_dependency_cache()
        self.assertTrue(z3_available(_probe=probe))

    def test_the_generation_is_not_consulted_on_every_call(self):
        """Re-probing per instruction would put an import attempt on the hot path."""
        calls = []

        def probe():
            calls.append(1)
            return True

        for _ in range(5):
            z3_available(_probe=probe)
        self.assertEqual(len(calls), 1)


class TestProofGateStatus(unittest.TestCase):
    """A proof gate that cannot be honoured must announce itself.

    z3 is not a dependency of this package: d810 installs it into a private
    directory (``~/.d810-speedups``) via ``install-speedups`` and prepends that
    to sys.path, pinning both the wheel and the native libz3.  Declaring
    z3-solver here would put a second copy in IDA's site-packages and let
    sys.path order decide which Python wrapper pairs with which libz3.

    The cost of that isolation is that a user can install everything and still
    have no z3.  With require_proof=True every candidate is then skipped, which
    is indistinguishable from "nothing matched" -- the same silent inertness
    that made mba-solve look like a no-op before.
    """

    def test_no_warning_when_proofs_can_be_produced(self):
        if not z3_available():
            self.skipTest("needs z3 present to assert the quiet path")
        self.assertIsNone(proof_gate_status(require_proof=True))

    def test_no_warning_when_the_caller_did_not_ask_for_proofs(self):
        """require_proof=False is a deliberate choice, not a broken install."""
        self.assertIsNone(proof_gate_status(require_proof=False))

    def test_warns_when_proof_required_but_z3_is_absent(self):
        if z3_available():
            self.skipTest("needs z3 absent to assert the loud path")
        message = proof_gate_status(require_proof=True)
        self.assertIsNotNone(message)

    def test_the_message_names_the_consequence_and_both_remedies(self):
        """A warning that does not say what to DO is noise.

        Both ways out are legitimate and the message offers them evenly:
        install z3, or turn the gate off. Running unproven rewrites is the
        user's call to make, so this reports the trade rather than editorialising
        about it.
        """
        message = proof_gate_status(require_proof=True, z3_present=False)
        assert message is not None
        self.assertIn("install-speedups", message)
        self.assertIn("no rewrites", message.lower())
        self.assertIn("require_proof", message)

    def test_the_message_does_not_disparage_turning_the_gate_off(self):
        """require_proof=false is a supported setting, not a mistake."""
        message = proof_gate_status(require_proof=True, z3_present=False)
        assert message is not None
        lowered = message.lower()
        for scold in ("not a substitute", "wrong direction", "should not", "unsafe"):
            self.assertNotIn(scold, lowered)

    def test_missing_z3_never_silently_changes_the_setting(self):
        """The status reports; it does not rewrite the user's configuration.

        Auto-flipping require_proof would make the applied-rewrite set depend on
        whether a solver happened to be installed, which is a surprise either
        way. Whether to run unproven rewrites stays an explicit choice.
        """
        self.assertIsInstance(proof_gate_status(require_proof=True, z3_present=False), str)
        self.assertIsNone(proof_gate_status(require_proof=False, z3_present=False))


class TestTimeoutSemantics(unittest.TestCase):
    def setUp(self):
        if not z3_available():
            self.skipTest("z3 not installed")

    def test_equivalent_pair_proves(self):
        # (a & b) + (a | b) == a + b, for all 32-bit a, b.
        a, b = V("a"), V("b")
        original = B("+", B("&", a, b), B("|", a, b))
        rewrite = B("+", a, b)
        self.assertIs(
            prove_equivalent(original, rewrite, ["a", "b"], 32),
            ProofResult.PROVED,
        )

    def test_inequivalent_pair_refutes(self):
        a, b = V("a"), V("b")
        self.assertIs(
            prove_equivalent(B("+", a, b), B("^", a, b), ["a", "b"], 32),
            ProofResult.REFUTED,
        )

    def test_starved_budget_never_reports_refuted(self):
        """A 1ms budget on a genuinely-equal pair must not say REFUTED.

        This is the safety property the whole inline-budget design rests on.
        z3 may still finish in under a millisecond, so PROVED is an acceptable
        outcome too -- what must never happen is REFUTED.
        """
        a, b = V("a"), V("b")
        original = B("*", B("+", a, b), B("+", a, b))
        rewrite = B(
            "+",
            B("+", B("*", a, a), B("*", C(2), B("*", a, b))),
            B("*", b, b),
        )
        verdict = prove_equivalent(original, rewrite, ["a", "b"], 32, timeout_ms=1)
        self.assertIn(verdict, (ProofResult.PROVED, ProofResult.UNKNOWN))
        self.assertIsNot(verdict, ProofResult.REFUTED)

    def test_default_timeout_is_used_when_unspecified(self):
        a = V("a")
        self.assertIs(
            prove_equivalent(a, a, ["a"], 32),
            ProofResult.PROVED,
        )



class TestThreadSafety(unittest.TestCase):
    """z3 objects are bound to a context, and a context is not thread-safe.

    The escalation prover runs on a worker thread while the rule proves inline
    on the main thread. Sharing the default context across the two raises
    "Z3Exception: context mismatch" -- and inside IDA that exception escapes
    check_and_replace into the Hex-Rays C++ callback, where it manifests as
    SIGSEGV rather than a traceback. Measured: EXIT=139 after two applications.

    Each thread must therefore build its own Context and create every term in
    it.
    """

    def setUp(self):
        if not z3_available():
            self.skipTest("z3 not installed")

    def test_accepts_an_explicit_context(self):
        import z3

        ctx = z3.Context()
        a, b = V("a"), V("b")
        verdict = prove_equivalent(
            B("+", B("&", a, b), B("|", a, b)),
            B("+", a, b),
            ["a", "b"],
            32,
            ctx=ctx,
        )
        self.assertIs(verdict, ProofResult.PROVED)

    def test_concurrent_proofs_with_per_thread_contexts_do_not_collide(self):
        import threading

        import z3

        errors: list[str] = []
        orig = B("*", B("+", V("a"), V("b")), B("+", V("a"), V("b")))
        rew = B(
            "+",
            B("+", B("*", V("a"), V("a")), B("*", C(2), B("*", V("a"), V("b")))),
            B("*", V("b"), V("b")),
        )

        def worker(n: int) -> None:
            ctx = z3.Context()
            try:
                for _ in range(15):
                    prove_equivalent(orig, rew, ["a", "b"], 32,
                                     timeout_ms=2000, ctx=ctx)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"thread {n}: {type(exc).__name__}: {exc}")

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])

if __name__ == "__main__":
    unittest.main()
