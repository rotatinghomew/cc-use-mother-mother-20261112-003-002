from __future__ import annotations

from collections import defaultdict, deque
from typing import Any, Iterable, Mapping

from .domain import fingerprint
from .errors import DomainError


class DependencyGraph:
    def __init__(self, capabilities: Iterable[Mapping[str, Any]], dependencies: Iterable[Mapping[str, Any]]) -> None:
        self.capabilities = {item["capability_id"]: dict(item) for item in capabilities}
        self.dependencies = [dict(item) for item in dependencies]
        self.requires: dict[str, set[str]] = defaultdict(set)
        self.after: dict[str, set[str]] = defaultdict(set)
        self.conflicts: dict[str, set[str]] = defaultdict(set)
        self._compile()

    def _compile(self) -> None:
        for item in self.dependencies:
            predecessor = item["predecessor"]
            successor = item["successor"]
            if predecessor not in self.capabilities or successor not in self.capabilities:
                raise DomainError("unknown_dependency_node", "dependency graph references an unknown capability")
            kind = item["type"]
            if kind == "requires":
                self.requires[successor].add(predecessor)
            elif kind == "after":
                self.after[successor].add(predecessor)
            elif kind == "conflicts":
                self.conflicts[predecessor].add(successor)
                self.conflicts[successor].add(predecessor)
            else:
                raise DomainError("unknown_dependency_type", "dependency graph has an unknown edge type")
        cycle = self.find_cycle()
        if cycle:
            raise DomainError("dependency_cycle", "capability dependency graph contains a cycle", details={"cycle": cycle})

    def predecessors(self, node: str) -> set[str]:
        return set(self.requires.get(node, set())) | set(self.after.get(node, set()))

    def find_cycle(self) -> list[str]:
        state: dict[str, int] = {node: 0 for node in self.capabilities}
        stack: list[str] = []

        def visit(node: str) -> list[str]:
            state[node] = 1
            stack.append(node)
            for predecessor in sorted(self.predecessors(node)):
                if state[predecessor] == 0:
                    found = visit(predecessor)
                    if found:
                        return found
                elif state[predecessor] == 1:
                    offset = stack.index(predecessor)
                    return stack[offset:] + [predecessor]
            stack.pop()
            state[node] = 2
            return []

        for node in sorted(self.capabilities):
            if state[node] == 0:
                found = visit(node)
                if found:
                    return found
        return []

    def topological_layers(self) -> list[list[str]]:
        outgoing: dict[str, set[str]] = defaultdict(set)
        indegree = {node: 0 for node in self.capabilities}
        for successor in self.capabilities:
            for predecessor in self.predecessors(successor):
                outgoing[predecessor].add(successor)
                indegree[successor] += 1
        frontier = sorted(node for node, degree in indegree.items() if degree == 0)
        layers: list[list[str]] = []
        visited = 0
        while frontier:
            layer = list(frontier)
            layers.append(layer)
            next_frontier: list[str] = []
            for node in layer:
                visited += 1
                for successor in sorted(outgoing.get(node, set())):
                    indegree[successor] -= 1
                    if indegree[successor] == 0:
                        next_frontier.append(successor)
            frontier = sorted(next_frontier)
        if visited != len(self.capabilities):
            raise DomainError("dependency_cycle", "capability dependency graph contains a cycle")
        return layers

    def transitive_requirements(self, node: str) -> list[str]:
        if node not in self.capabilities:
            raise DomainError("unknown_capability", "unknown capability", details={"capability_id": node})
        result: set[str] = set()
        queue = deque(sorted(self.requires.get(node, set())))
        while queue:
            current = queue.popleft()
            if current in result:
                continue
            result.add(current)
            queue.extend(sorted(self.requires.get(current, set())))
        return sorted(result)

    def validate_enabled_set(self, enabled: Iterable[str]) -> dict[str, Any]:
        selected = set(enabled)
        unknown = sorted(selected - set(self.capabilities))
        missing: dict[str, list[str]] = {}
        conflicts: list[tuple[str, str]] = []
        for node in sorted(selected & set(self.capabilities)):
            required = set(self.transitive_requirements(node))
            absent = sorted(required - selected)
            if absent:
                missing[node] = absent
            for conflict in sorted(self.conflicts.get(node, set()) & selected):
                pair = tuple(sorted((node, conflict)))
                if pair not in conflicts:
                    conflicts.append(pair)
        return {
            "valid": not unknown and not missing and not conflicts,
            "unknown": unknown,
            "missing_requirements": missing,
            "conflicts": [list(item) for item in sorted(conflicts)],
        }

    def rollout_stages(self) -> list[dict[str, Any]]:
        stages: list[dict[str, Any]] = []
        for index, layer in enumerate(self.topological_layers(), start=1):
            stages.append(
                {
                    "stage": index,
                    "capabilities": layer,
                    "risk_levels": sorted({self.capabilities[node]["risk_level"] for node in layer}),
                    "required_predecessors": sorted(
                        {predecessor for node in layer for predecessor in self.predecessors(node)}
                    ),
                }
            )
        return stages

    def as_dict(self) -> dict[str, Any]:
        value = {
            "nodes": sorted(self.capabilities),
            "dependencies": sorted(
                self.dependencies,
                key=lambda item: (item["type"], item["predecessor"], item["successor"]),
            ),
            "layers": self.topological_layers(),
        }
        value["graph_digest"] = fingerprint(value)
        return value


def build_dependency_graph(plan: Mapping[str, Any]) -> dict[str, Any]:
    graph = DependencyGraph(plan["capabilities"], plan["dependencies"])
    enabled = [item["capability_id"] for item in plan["capabilities"]]
    validation = graph.validate_enabled_set(enabled)
    if not validation["valid"]:
        raise DomainError("invalid_capability_set", "plan capabilities violate dependency constraints", details=validation)
    result = graph.as_dict()
    result["stages"] = graph.rollout_stages()
    return result

