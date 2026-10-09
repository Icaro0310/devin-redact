"""ClusterFuzzLite fuzz target: redact_text/scan_text on arbitrary input."""

import sys

import atheris

with atheris.instrument_imports():
    from devin_redact import engine


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 4096))
    redacted, replacements = engine.redact_text(text)
    assert isinstance(redacted, str)
    assert isinstance(replacements, list)
    engine.scan_text(text, file="fuzz.py", location="fuzz")


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
