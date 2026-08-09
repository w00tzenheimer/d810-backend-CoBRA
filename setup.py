"""Build the CoBRA solver binding.

Unlike d810, where this extension was optional and the wheel had to remain
installable without it, the binding is the entire point of this package. So a
build that cannot produce it FAILS rather than quietly yielding an inert
install -- the failure mode we spent a long time chasing in d810 was exactly a
wheel that installed cleanly and simplified nothing.

The C++ side is built by ``tools/build_cobra.py`` (CMake + Ninja), which
produces the layout consumed here.
"""

from __future__ import annotations

import os
import pathlib
import platform

from setuptools import setup

OSTYPE = platform.system()
HERE = pathlib.Path(__file__).parent.resolve()

#: Layout mirrors d810 itself, which keeps shared C headers in ``src/include``
#: rather than inside the importable package. Both ``_cobra.pyx`` and
#: ``cobra_shim.cpp`` include the header by bare name, so this must be on the
#: include path for either to compile.
#:
#: Keeping them out of ``src/d810_cobra`` means the wheel ships only what is
#: importable: the header and the C++ shim are build inputs, and a consumer who
#: pip-installs a built wheel has no use for either.
SRC = HERE / "src"
INCLUDE_DIR = SRC / "include"


def _first_existing(root: pathlib.Path, candidates: tuple[str, ...]):
    for rel in candidates:
        candidate = root / rel
        if candidate.exists():
            return candidate
    return None


def get_cobra_ext_modules():
    try:
        from Cython.Build import cythonize
        from setuptools import Extension
    except ImportError:  # pragma: no cover - build-time only
        raise ImportError("Cython is required to build the CoBRA binding")

    # Default to the vendored submodule so `pip install -e .` works in a
    # checkout with no environment set up. CI overrides this for the flat
    # artifact layout.
    cobra_root = os.environ.get("COBRA_ROOT") or str(HERE / "third_party" / "cobra")
    root = pathlib.Path(cobra_root)
    if not root.is_dir():
        raise RuntimeError(
            f"COBRA_ROOT={root} does not exist. Either init the submodule\n"
            "  git submodule update --init --recursive\n"
            "and run  python tools/build_cobra.py , or point COBRA_ROOT at a\n"
            "prebuilt cobra-core bundle."
        )

    # TWO accepted layouts. The flat one exists so a released/CI static-lib
    # bundle can be consumed directly -- requiring callers to reshape a
    # download into a fake build tree is pure friction, and reshaping inside CI
    # just relocates it.
    #
    #   FLAT (release / CI artifact):  <root>/lib/*.{a,lib}   <root>/include/
    #   BUILD TREE (local checkout):   <root>/build/lib/core/
    #                                  <root>/build-deps/install/{lib*,include}/
    flat_lib = root / "lib"
    flat_inc = root / "include"
    is_flat = flat_lib.is_dir() and any(flat_lib.glob("*cobra-core*"))

    if is_flat:
        include_dirs = [str(INCLUDE_DIR), str(flat_inc)]
        library_dirs = [str(flat_lib)]
    else:
        # Pick ONE dependency prefix and one core build; globbing several and
        # merging them silently mixes incompatible trees.
        deps_prefix = _first_existing(
            root, ("build-deps/install", "build-deps-nollvm/install")
        )
        core_dir = _first_existing(root, ("build/lib/core", "build-nollvm/lib/core"))
        if deps_prefix is None or core_dir is None:
            raise RuntimeError(
                f"COBRA_ROOT={root} does not look built. Accepted layouts:\n"
                f"  flat:       {root}/lib/*cobra-core* + {root}/include/\n"
                f"  build tree: {root}/build/lib/core + {root}/build-deps/install\n"
                "Run: python tools/build_cobra.py"
            )
        include_dirs = [
            str(INCLUDE_DIR),
            str(root / "include"),
            str(deps_prefix / "include"),
        ]
        # lib vs lib64: manylinux is RHEL-based, where CMAKE_INSTALL_LIBDIR
        # defaults to lib64, so never hardcode "lib".
        library_dirs = [str(core_dir)] + [
            str(p) for p in sorted(deps_prefix.glob("lib*")) if p.is_dir()
        ]

    # CoBRA requires C++23 (Result.h uses std::expected).
    std_args = ["/std:c++latest"] if OSTYPE == "Windows" else ["-std=c++23"]

    # abseil scatters constants and singletons (container_internal::kSooControl,
    # MixingHashState::kSeed, Mutex, Now, ...) across archive members that
    # nothing else references, so a normal -l link never pulls them in. Python
    # extensions link with -undefined dynamic_lookup, so this does NOT fail the
    # link -- it fails later at dlopen with "symbol not found in flat
    # namespace", which is much harder to diagnose. Force every abseil archive
    # in and let the linker dead-strip the remainder.
    #
    # MSVC emits absl_base.lib; Unix toolchains emit libabsl_base.a. Globbing
    # only the Unix shape silently yields NOTHING on Windows and the force-load
    # never happens -- again a load-time failure, not a link-time one. An empty
    # match is therefore fatal.
    _absl_pattern = "absl_*.lib" if OSTYPE == "Windows" else "libabsl_*.a"
    absl_archives = [
        str(p) for d in library_dirs for p in sorted(pathlib.Path(d).glob(_absl_pattern))
    ]
    if not absl_archives:
        raise RuntimeError(
            f"no abseil archives matched {_absl_pattern!r} under {library_dirs}. "
            "Without force-loading them the extension links but fails at import "
            "with missing absl symbols; refusing to build a broken binding."
        )
    if OSTYPE == "Darwin":
        link_args = [f"-Wl,-force_load,{a}" for a in absl_archives]
        link_args.append("-Wl,-dead_strip")
    elif OSTYPE == "Linux":
        link_args = [
            "-Wl,--whole-archive",
            *absl_archives,
            "-Wl,--no-whole-archive",
            "-Wl,--gc-sections",
        ]
    else:
        link_args = [f"/WHOLEARCHIVE:{a}" for a in absl_archives]

    return cythonize(
        Extension(
            "d810_cobra._cobra",
            [
                "src/d810_cobra/_cobra.pyx",
                "src/cpp/cobra_shim.cpp",
            ],
            language="c++",
            include_dirs=include_dirs,
            library_dirs=library_dirs,
            libraries=["cobra-core"],
            extra_compile_args=std_args,
            extra_link_args=link_args,
        ),
        compiler_directives={"language_level": "3", "binding": True},
    )


setup(ext_modules=get_cobra_ext_modules())
