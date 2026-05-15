"""Command-line entrypoints (REPL + batch prompt) and runtime wiring.

Importing this package (or any submodule) triggers the agent_runner
injection that scheduling and team need.
"""
from minicode.agent.loop import agent_loop
import minicode.tools.scheduling as _sched
import minicode.tools.team as _team

_sched.agent_runner = agent_loop
_team.agent_runner = agent_loop
