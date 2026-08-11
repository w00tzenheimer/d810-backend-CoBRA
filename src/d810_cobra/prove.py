"""Prove two expression trees equivalent with Z3.  No IDA dependency.

The obligation is **tree vs tree over free leaf variables**, not
``minsn`` vs ``minsn``.  A candidate's original instruction is only a fragment
(``and eax, ecx, ecx``); the expression under test is the def-use-inlined tree
spanning several instructions, so there is no single instruction to compare
against.

``z3`` is optional -- it is not a declared d810 dependency -- so its absence is
reported as ``UNAVAILABLE`` rather than raised.
"""

from __future__ import annotations

import enum

# z3-solver is optional AND arrives late.
#
# It is not on sys.path when the interpreter starts inside IDA. d810 puts it
# there: importing d810 runs ensure_speedups_on_path(), which prepends
# ~/.d810-speedups and pins the matching native libz3 through
# builtins.Z3_LIB_DIRS.
#
# So a module-scope `import z3` answered a question about IMPORT ORDER rather
# than about the environment. Importing this module before d810 pinned
# availability False for the life of the process, and with require_proof=True
# that skips every candidate and applies nothing -- indistinguishable from "the
# solver matched nothing" (d81-ni1k). It also made installing z3 at runtime
# useless, since the answer could not change without restarting IDA.
#
# Resolved on first use and cached. The cache is what keeps the hot path cheap:
# check_and_replace runs per instruction.
z3 = None  # type: ignore[assignment]
_Z3_AVAILABLE: bool | None = None
#: Generation the cached answer was computed against; see _current_generation.
_Z3_GENERATION: int = -1


def _current_generation() -> int:
    """d810's optional-dependency generation, or 0 if it does not publish one.

    z3 can appear DURING a session: the speedups directory may be created by an
    installer while IDA is running.  d810 bumps this counter when that happens,
    so a cached "absent" can be detected as stale without re-attempting the
    import on every call -- and without d810 needing to know this package
    exists.
    """
    try:
        from d810.speedups.bootstrap import optional_dependency_generation

        return int(optional_dependency_generation())
    except Exception:  # noqa: BLE001 - older d810, or none at all
        return 0


def _probe_z3() -> bool:
    """Attempt the import now, binding the module for the proof helpers.

    Installs the speedups path itself rather than relying on someone having
    imported d810 first.  ``ensure_speedups_on_path`` is idempotent and cheap
    (a directory check plus at most one ``sys.path`` insert), and calling it
    here is what makes availability a fact about the ENVIRONMENT instead of a
    fact about import order.  d810 is a hard dependency of this package, so the
    import is always legitimate; it is still guarded because a broken or
    partial d810 must not turn "no proofs" into an exception on the hot path.
    """
    global z3
    try:
        from d810.speedups.bootstrap import ensure_speedups_on_path

        ensure_speedups_on_path()
    except Exception:  # noqa: BLE001 - absence is a valid answer, not an error
        pass
    try:
        import z3 as _z3
    except ImportError:  # pragma: no cover - depends on environment
        return False
    z3 = _z3
    return True


def reset_z3_detection() -> None:
    """Forget the cached answer so the next query re-probes.

    Called after installing solver support at runtime: without it the process
    would keep serving the pre-install answer until IDA restarts.
    """
    global _Z3_AVAILABLE
    _Z3_AVAILABLE = None


class ProofResult(enum.Enum):
    PROVED = "proved"
    REFUTED = "refuted"
    #: Solver gave up. Must be treated as failure: the timeout is a yield
    #: control, and at 20s three of sixty candidates timed out that were all
    #: provable at 300s. Log it distinctly from REFUTED -- they mean very
    #: different things.
    UNKNOWN = "unknown"
    UNAVAILABLE = "unavailable"


#: Multiplication is where bitvector reasoning gets hard; be generous.  This
#: is the budget for the OFF-critical-path prover, which nobody is waiting on.
DEFAULT_TIMEOUT_MS = 120_000

#: Budget for a proof that a live decompilation is blocked on.
#:
#: Set from measurement, not taste.  Sorted proof times (ms) over the 14
#: accepted candidates on VM_DecryptPacket:
#:
#:     0  1  3  8  115  197  284  440  701  1611  6213  18554  68113  93610
#:
#: 98% of total proof time sits in 4 of those 14, so a tight budget sheds
#: almost all the cost and little of the value: 500ms keeps 8/14 for 4.05s of
#: inline time, while 1000ms buys exactly one more proof for +2.7s and 2000ms
#: buys two more for +7.3s.
#:
#: A second sweep, on sub_7FF85A852A00 (13 accepted candidates, measured
#: against baseline gen_microcode at MMAT_GLBOPT2), located the saturation
#: point that the first ladder stopped short of:
#:
#:      500ms ->  7 proved,  6 starved,   3.62s
#:     1500ms ->  9 proved,  4 starved,   8.32s
#:     4000ms ->  9 proved,  4 starved,  20.75s
#:
#: The gain SATURATES at 1500ms: 4000ms buys nothing for 2.5x the time, so the
#: four that remain are genuinely hard rather than clipped.  Both functions
#: agree that ~1500ms buys about two more proofs for about +5s, which is why
#: the budget sits there rather than at the earlier 500ms.
#:
#: Counts near the wall jitter by one -- repeat runs of the same sweep gave 6
#: and 7 proofs at 500ms -- so treat +/-1 as noise and the saturation point,
#: not the absolute count, as the signal.
#:
#: Raising this costs FIRST-PASS LATENCY, not capability, and only on a cold
#: cache.  A starved proof yields UNKNOWN, which the caller treats as "skip",
#: but it escalates to DEFAULT_TIMEOUT_MS off the critical path, lands in the
#: rewrite table, and is flushed to the durable proof cache -- so a later
#: decompile applies it as a table hit with no inline proof at all.  Starved
#: means deferred, not lost.
INLINE_TIMEOUT_MS = 1500


def z3_available(*, _probe=_probe_z3) -> bool:
    """Is z3 importable right now? Probed once, then cached.

    ``_probe`` is an injection point for tests, which must exercise both the
    present and absent paths on a single machine.
    """
    global _Z3_AVAILABLE, _Z3_GENERATION
    generation = _current_generation()
    if _Z3_AVAILABLE is None or generation != _Z3_GENERATION:
        _Z3_AVAILABLE = bool(_probe())
        _Z3_GENERATION = generation
    return _Z3_AVAILABLE


def proof_gate_status(
    require_proof: bool, *, z3_present: bool | None = None
) -> str | None:
    """Warning text when a requested proof gate cannot be honoured, else None.

    z3 is deliberately NOT a dependency of this package.  d810 installs it into
    a private directory (``~/.d810-speedups``) with ``install-speedups`` and
    prepends that to ``sys.path``, pinning both the wheel and the native
    ``libz3`` it loads.  A second ``z3-solver`` in IDA's site-packages would let
    path order decide which Python wrapper pairs with which native library, and
    a mismatched pair is a crash rather than an ImportError.

    The cost of that isolation is a reachable state where everything installs
    cleanly and no proof can be produced.  ``require_proof`` then skips EVERY
    candidate, which reads exactly like "the solver found nothing" -- so this
    exists to make the difference visible.

    Advisory only: it reports the state and both ways out, and changes nothing.
    ``require_proof=False`` is a supported setting, so running rewrites without
    proof is the caller's decision to make; this does not flip it for them,
    because an applied-rewrite set that silently depended on whether a solver
    happened to be installed would be the greater surprise.

    Nothing is emitted when ``require_proof`` is already False -- that user has
    chosen, and does not need telling.

    *z3_present* overrides detection, for tests that must assert both paths on
    one machine.
    """
    present = z3_available() if z3_present is None else z3_present
    if not require_proof or present:
        return None
    return (
        "proofs are required but z3 is unavailable, so no rewrites will be "
        "applied. To proceed, either install z3 with the 'install-speedups' "
        "command that ships with d810 (it places z3-solver in "
        "~/.d810-speedups), or set require_proof=false to apply solver "
        "rewrites without proof."
    )


def _to_z3(tree: dict, env: dict, bits: int, ctx=None):
    kind = tree["kind"]
    if kind == "const":
        # The context must be threaded all the way down: a term built in the
        # default context and combined with one built elsewhere raises
        # "Z3Exception: context mismatch".
        return z3.BitVecVal(tree["value"] & ((1 << bits) - 1), bits, ctx=ctx)
    if kind == "var":
        return env[tree["name"]]
    if kind == "un":
        operand = _to_z3(tree["a"], env, bits, ctx)
        return (-operand) if tree["op"] == "-" else (~operand)

    left = _to_z3(tree["a"], env, bits, ctx)
    right = _to_z3(tree["b"], env, bits, ctx)
    op = tree["op"]
    if op == "+":
        return left + right
    if op == "-":
        return left - right
    if op == "*":
        return left * right
    if op == "&":
        return left & right
    if op == "|":
        return left | right
    if op == "^":
        return left ^ right
    raise ValueError(f"unknown operator {op!r}")


def prove_equivalent(
    original: dict,
    rewrite: dict,
    leaf_names: list[str] | tuple[str, ...],
    bitwidth: int,
    *,
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
    ctx=None,
) -> ProofResult:
    """Return whether *rewrite* is equivalent to *original* for all inputs.

    ``ctx`` is a ``z3.Context``.  **Every thread must supply its own.**  z3
    terms belong to a context and a context is not thread-safe: sharing the
    default one between the inline proof on the main thread and the escalation
    worker raises "Z3Exception: context mismatch", and inside IDA that
    exception escapes the rule into the Hex-Rays C++ callback and takes the
    process down with SIGSEGV.  Measured: EXIT=139 after two applications.
    """
    if not z3_available():
        return ProofResult.UNAVAILABLE

    env = {
        name: z3.BitVec(f"v{i}", bitwidth, ctx=ctx)
        for i, name in enumerate(leaf_names)
    }
    solver = z3.Solver(ctx=ctx)
    solver.set("timeout", timeout_ms)
    solver.add(
        _to_z3(original, env, bitwidth, ctx) != _to_z3(rewrite, env, bitwidth, ctx)
    )

    verdict = solver.check()
    if verdict == z3.unsat:
        return ProofResult.PROVED
    if verdict == z3.sat:
        return ProofResult.REFUTED
    return ProofResult.UNKNOWN
