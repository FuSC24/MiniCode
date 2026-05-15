#!/usr/bin/env python3
"""MiniCode entrypoint - see minicode/ package for implementation."""
import sys

from minicode.commands.repl import repl
from minicode.commands.batch import run_prompt
from minicode.prompts import HELP_TEXT


if __name__ == "__main__":
    if "--help" in sys.argv:
        print(HELP_TEXT)
        sys.exit(0)
    if "--version" in sys.argv:
        print("minicode 0.1")
        sys.exit(0)
    if ("--prompt" in sys.argv
            or any(a.startswith("--prompt=") for a in sys.argv)
            or "--prompt-file" in sys.argv
            or any(a.startswith("--prompt-file=") for a in sys.argv)):
        run_prompt()
    repl()
