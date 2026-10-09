#!/bin/bash -eu
pip3 install atheris pyinstaller
pip3 install -e packages/redact
compile_python_fuzzer packages/redact/fuzz/fuzz_redact.py
