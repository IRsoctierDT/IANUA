# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Coverage-guided fuzzing of the surfaces that parse untrusted input.

``targets`` holds one bytes-in function per surface, each asserting the
invariants that surface documents. ``__main__`` runs them under Atheris (Linux
x86_64, Python >= 3.12: ``pip install -e ".[fuzz]"``); ``test_fuzz_corpus``
replays the seeds through the same functions on every platform, Atheris or not.

    python -m tests.fuzz.seeds normalize corpus/
    python -m tests.fuzz normalize -max_total_time=60 corpus/
"""
