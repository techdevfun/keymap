"""keymap — find where your API keys actually live.

A local, read-only auditor. It scans the config files your agent tools,
CLIs and shells really read, and reports *where* each provider key sits,
whether it is sprawled across files, world-readable, sitting in shell
history, or at risk of being committed — without ever printing key
material and without any network access.
"""

__version__ = "0.1.0"
