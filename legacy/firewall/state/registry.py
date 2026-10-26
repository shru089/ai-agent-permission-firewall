"""
Registry dependency interface for tools, resource classifications, and destination zones.
Source: 05_TECHNICAL_SPEC.md §7.1, §8.1

Note: The files under config/ (e.g. registry.yaml) are empty placeholders in the repository.
Production configuration loading is intentionally decoupled from runtime transition logic.
Use explicit registry instances or load_test_registry() in tests and development.
"""

from pathlib import Path
from typing import Any, Optional

import yaml  # type: ignore[import-untyped]
from pydantic import BaseModel, ConfigDict, Field

from firewall.contracts.enums import Classification, ToolClass, Zone


class ResourceInfo(BaseModel):
    """Classification and metadata for a registered resource (AS-1)."""

    classification: Classification
    rows: Optional[int] = None
    model_config = ConfigDict(extra="forbid")


class DestinationInfo(BaseModel):
    """Zone assignment for a registered export destination (AS-2)."""

    zone: Zone
    model_config = ConfigDict(extra="forbid")


class ToolInfo(BaseModel):
    """Sensitivity class and argument specification for a registered tool."""

    tool_class: ToolClass
    args: dict[str, Any] = Field(default_factory=dict)
    model_config = ConfigDict(extra="forbid")


class Registry:
    """
    Immutable registry providing trusted resource classifications, destination zones,
    and tool metadata required by the deterministic state engine and policy engine (INV-07, A-05).
    """

    def __init__(
        self,
        resources: Optional[dict[str, ResourceInfo | dict[str, Any]]] = None,
        destinations: Optional[dict[str, DestinationInfo | dict[str, Any]]] = None,
        tools: Optional[dict[str, ToolInfo | dict[str, Any]]] = None,
        version: str = "0.1.0",
    ) -> None:
        self.version = version
        self._resources: dict[str, ResourceInfo] = {}
        self._destinations: dict[str, DestinationInfo] = {}
        self._tools: dict[str, ToolInfo] = {}

        if resources:
            for r_k, r_v in resources.items():
                if isinstance(r_v, ResourceInfo):
                    self._resources[r_k] = r_v
                else:
                    self._resources[r_k] = ResourceInfo.model_validate(r_v)

        if destinations:
            for d_k, d_v in destinations.items():
                if isinstance(d_v, DestinationInfo):
                    self._destinations[d_k] = d_v
                else:
                    self._destinations[d_k] = DestinationInfo.model_validate(d_v)

        if tools:
            for t_k, t_v in tools.items():
                if isinstance(t_v, ToolInfo):
                    self._tools[t_k] = t_v
                else:
                    self._tools[t_k] = ToolInfo.model_validate(t_v)

    def get_resource(self, ref: str) -> Optional[ResourceInfo]:
        """Look up resource metadata by reference identifier."""
        return self._resources.get(ref)

    def get_resource_classification(self, ref: str) -> Classification:
        """
        Return classification for resource. If unknown or not found, returns Classification.UNKNOWN.
        Never silently assumes public or safe (SO-5, INV-04).
        """
        info = self._resources.get(ref)
        if info is None:
            return Classification.UNKNOWN
        return info.classification

    def get_resource_rows(self, ref: str) -> Optional[int]:
        """Return expected row count for resource if registered."""
        info = self._resources.get(ref)
        if info is None:
            return None
        return info.rows

    def has_resource(self, ref: str) -> bool:
        """Check whether a resource reference exists in the registry."""
        return ref in self._resources

    def get_destination(self, ref: str) -> Optional[DestinationInfo]:
        """Look up destination metadata by reference identifier."""
        return self._destinations.get(ref)

    def get_destination_zone(self, ref: str) -> Zone:
        """
        Return destination network/storage zone. If unknown, returns Zone.UNKNOWN.
        Never silently assumes internal (SO-5, INV-04).
        """
        info = self._destinations.get(ref)
        if info is None:
            return Zone.UNKNOWN
        return info.zone

    def has_destination(self, ref: str) -> bool:
        """Check whether a destination reference exists in the registry."""
        return ref in self._destinations

    def get_tool(self, tool_name: str) -> Optional[ToolInfo]:
        """Look up tool sensitivity class and argument schema."""
        return self._tools.get(tool_name)

    def get_facts_for_action(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """
        Extract only the registry facts corresponding to entities explicitly named
        in action arguments (allow-listed projection for MonitorView).
        """
        facts: dict[str, Any] = {}
        for key in ("resource_ref", "dataset", "source"):
            val = arguments.get(key)
            if isinstance(val, str) and val in self._resources:
                facts[val] = self._resources[val].model_dump()
        for key in ("destination_ref", "destination", "target"):
            val = arguments.get(key)
            if isinstance(val, str) and val in self._destinations:
                facts[val] = self._destinations[val].model_dump()
        return facts

    def snapshot(self) -> dict[str, Any]:
        """Produce an immutable dictionary snapshot of registry contents."""
        return {
            "version": self.version,
            "resources": {k: v.model_dump() for k, v in self._resources.items()},
            "destinations": {k: v.model_dump() for k, v in self._destinations.items()},
            "tools": {k: v.model_dump() for k, v in self._tools.items()},
        }


def load_test_registry(data: dict[str, Any]) -> Registry:
    """Helper to construct an explicitly labelled test registry from raw dict."""
    return Registry(
        resources=data.get("resources"),
        destinations=data.get("destinations"),
        tools=data.get("tools"),
        version=data.get("registry_version", "0.1.0"),
    )


def load_registry_from_yaml(path: str | Path) -> Registry:
    """
    Load a registry definition from a YAML file.
    Note: Raises ValueError if the file is empty or missing required sections.
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Registry file not found: {file_path}")
    raw_content = file_path.read_text(encoding="utf-8").strip()
    if not raw_content:
        raise ValueError(
            f"Registry file at {file_path} is empty. Production registry entries are not defined."
        )
    parsed = yaml.safe_load(raw_content)
    if not isinstance(parsed, dict):
        raise ValueError(f"Malformed YAML in registry file: {file_path}")
    return load_test_registry(parsed)
