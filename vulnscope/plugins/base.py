from typing import List, Protocol, Any


class VulnScopePlugin(Protocol):
    name: str

    def on_start(self, argv: list[str]) -> None:
        ...

    def on_args_parsed(self, args: Any) -> None:
        ...

    def on_before_command(self, args: Any) -> None:
        ...

    def on_after_command(self, args: Any, result: Any) -> None:
        ...


_PLUGINS: List[VulnScopePlugin] = []


def register_plugin(plugin: VulnScopePlugin) -> None:
    _PLUGINS.append(plugin)


def get_plugins() -> List[VulnScopePlugin]:
    return list(_PLUGINS)

