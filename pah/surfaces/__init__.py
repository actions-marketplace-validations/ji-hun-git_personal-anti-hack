"""Execution surfaces: everything in a repo that runs, or changes what an agent does, without being read first.

Each handler parses one kind of file, records the surface (what runs and what triggers it), analyzes every command
it finds, and marks files those commands reference as "autoexec" so their content is judged as code that runs on
its own.

The handlers are grouped by what they read: agent_configs, instructions (with skills), mcp, ide, workflows,
git and env, on top of base (files, state, command parsing) and rules. dispatch decides which handlers read a file.
"""
from __future__ import annotations

from .base import (File, State, as_command, exec_refs_in_command, line_of, load_jsonc, load_toml, refs_in_command,
                   walk_commands)
from .agent_setup import toxic_flows
from .dispatch import dispatch
from .instructions import AUTO_LOADED, SETUP_DOC, unpinned_runner, well_known

__all__ = [
    "AUTO_LOADED",
    "File",
    "SETUP_DOC",
    "State",
    "as_command",
    "dispatch",
    "exec_refs_in_command",
    "line_of",
    "load_jsonc",
    "load_toml",
    "refs_in_command",
    "toxic_flows",
    "unpinned_runner",
    "walk_commands",
    "well_known",
]
