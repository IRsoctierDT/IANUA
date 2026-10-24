# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Run one fuzz target under Atheris.

    python -m tests.fuzz <target> [libFuzzer flags] [corpus directories]

Instrumentation is the whole of the coverage signal, and both calls below are
load-bearing:

* ``instrument_imports()`` around the import of the targets instruments the code
  under test. Measured with a planted four-byte check: uninstrumented, two
  million inputs never left the one-byte starting corpus; instrumented, the
  same check fell almost at once.
* ``instrument_all()`` reaches what was loaded *before* that block, and that
  includes ``ipaddress``, because ``import atheris`` imports it itself. Measured
  over 45-60 seconds per target: egress went from 60 coverage edges to 197 and
  projection from 107 to 384, normalize gained 8% and key-value nothing, at no
  speed cost except egress (49k to 30k inputs a second).

``test_fuzz_corpus.py`` holds both calls in place.
"""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from tests.fuzz.targets import TARGETS

atheris.instrument_all()


def main(argv: list[str]) -> None:
    """Pop the target name off ``argv`` and hand the rest to libFuzzer."""
    if len(argv) < 2 or argv[1] not in TARGETS:
        print(f"usage: python -m tests.fuzz <{'|'.join(sorted(TARGETS))}> [libFuzzer flags]")
        raise SystemExit(2)
    target = TARGETS[argv.pop(1)]
    atheris.Setup(argv, target)
    atheris.Fuzz()


if __name__ == "__main__":
    main(sys.argv)
