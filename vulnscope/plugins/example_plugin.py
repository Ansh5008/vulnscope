"""
Example plugin for VulnScope.

Demonstrates how to hook into the CLI lifecycle.
"""

from typing import Any

from vulnscope.plugins.base import VulnScopePlugin, register_plugin


class DebugLoggingPlugin:
    name = "debug-logging"

    def on_start(self, argv: list[str]) -> None:
        pass

    def on_args_parsed(self, args: Any) -> None:
        pass

    def on_before_command(self, args: Any) -> None:
        pass

    def on_after_command(self, args: Any, result: Any) -> None:
        pass


register_plugin(DebugLoggingPlugin())

