"""
process_tree.py - Parent-Child Process Tree Analyzer
=======================================================
Builds complete process trees and detects suspicious parent-child
relationships such as Office apps spawning PowerShell, LOLBin abuse,
and other known attack chains.

Author: Security Research Team
Version: 1.0.0
"""

import threading
from collections import defaultdict
from typing import Optional

import psutil

from modules.alert_manager import AlertManager
from modules.database_manager import DatabaseManager
from modules.logger import get_logger
from modules.utils import load_json_config, safe_proc_attr

logger = get_logger("process_tree")

DETECTION_RULES_PATH = "config/detection_rules.json"


class ProcessNode:
    """Represents a single node in the process tree."""

    def __init__(self, pid: int, name: str, exe_path: str = "N/A") -> None:
        """
        Initialize a ProcessNode.

        Args:
            pid: Process ID.
            name: Process name.
            exe_path: Executable path.
        """
        self.pid = pid
        self.name = name
        self.exe_path = exe_path
        self.children: list["ProcessNode"] = []
        self.parent: Optional["ProcessNode"] = None

    def to_dict(self, depth: int = 0) -> dict:
        """Serialize the node and its descendants to a dictionary."""
        return {
            "pid": self.pid,
            "name": self.name,
            "exe_path": self.exe_path,
            "depth": depth,
            "children": [child.to_dict(depth + 1) for child in self.children],
        }

    def __repr__(self) -> str:
        return f"ProcessNode(pid={self.pid}, name={self.name})"


class ProcessTreeAnalyzer:
    """
    Builds and analyzes the system-wide process tree.
    Detects suspicious parent-child chains using configurable rules.
    """

    def __init__(self, db_manager: DatabaseManager, alert_manager: AlertManager) -> None:
        """
        Initialize the ProcessTreeAnalyzer.

        Args:
            db_manager: Database persistence layer.
            alert_manager: Alert dispatch engine.
        """
        self._db = db_manager
        self._alerts = alert_manager
        self._lock = threading.Lock()
        self._rules_config = load_json_config(DETECTION_RULES_PATH)
        self._parent_child_rules = self._load_parent_child_rules()
        self._tree_cache: dict[int, ProcessNode] = {}
        self._root_nodes: list[ProcessNode] = []
        logger.info("ProcessTreeAnalyzer initialized.")

    def _load_parent_child_rules(self) -> list[dict]:
        """
        Extract parent-child detection rules from config.

        Returns:
            List of rule dicts with parent_processes and child_processes.
        """
        rules = []
        for rule in self._rules_config.get("rules", []):
            if rule.get("enabled") and "parent_processes" in rule and "child_processes" in rule:
                rules.append({
                    "id": rule["id"],
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "category": rule["category"],
                    "parents": [p.lower() for p in rule["parent_processes"]],
                    "children": [c.lower() for c in rule["child_processes"]],
                    "mitre": rule.get("mitre_technique", "N/A"),
                    "recommendation": rule.get("recommendation", "Investigate immediately."),
                })
        logger.info(f"Loaded {len(rules)} parent-child detection rules.")
        return rules

    def reload_rules(self) -> None:
        """Reload detection rules from disk."""
        self._rules_config = load_json_config(DETECTION_RULES_PATH)
        self._parent_child_rules = self._load_parent_child_rules()
        logger.info("ProcessTreeAnalyzer rules reloaded.")

    def build_process_tree(self) -> list[ProcessNode]:
        """
        Build a complete process tree from all running processes.

        Returns:
            List of root ProcessNode objects.
        """
        all_nodes: dict[int, ProcessNode] = {}
        child_map: dict[int, list[int]] = defaultdict(list)

        # Collect all processes
        for proc in psutil.process_iter(["pid", "name", "exe", "ppid"]):
            try:
                pid = safe_proc_attr(proc, "pid", 0)
                name = safe_proc_attr(proc, "name", "Unknown")
                exe = safe_proc_attr(proc, "exe", "N/A") or "N/A"
                ppid = safe_proc_attr(proc, "ppid", 0)

                node = ProcessNode(pid=pid, name=name, exe_path=exe)
                all_nodes[pid] = node
                if ppid and ppid != pid:
                    child_map[ppid].append(pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Build tree relationships
        root_nodes: list[ProcessNode] = []
        for pid, node in all_nodes.items():
            children_pids = child_map.get(pid, [])
            for child_pid in children_pids:
                child_node = all_nodes.get(child_pid)
                if child_node:
                    child_node.parent = node
                    node.children.append(child_node)

        # Roots = nodes with no parent in our map
        for node in all_nodes.values():
            if node.parent is None:
                root_nodes.append(node)

        with self._lock:
            self._tree_cache = all_nodes
            self._root_nodes = root_nodes

        logger.info(f"Process tree built: {len(all_nodes)} nodes, {len(root_nodes)} roots.")
        return root_nodes

    def analyze_relationships(self) -> list[dict]:
        """
        Scan all parent-child process pairs against detection rules.

        Returns:
            List of detected suspicious relationship dicts.
        """
        findings: list[dict] = []

        # Rebuild tree to get fresh data
        self.build_process_tree()

        with self._lock:
            nodes = dict(self._tree_cache)

        for node in nodes.values():
            if not node.children:
                continue
            parent_name = node.name.lower()
            for child in node.children:
                child_name = child.name.lower()
                finding = self._check_rule_match(
                    parent_name=parent_name,
                    child_name=child_name,
                    parent_node=node,
                    child_node=child,
                )
                if finding:
                    findings.append(finding)

        logger.info(f"Process tree analysis: {len(findings)} suspicious relationships found.")
        return findings

    def _check_rule_match(
        self,
        parent_name: str,
        child_name: str,
        parent_node: ProcessNode,
        child_node: ProcessNode,
    ) -> Optional[dict]:
        """
        Check if a parent-child process pair matches any detection rule.

        Args:
            parent_name: Lowercase parent process name.
            child_name: Lowercase child process name.
            parent_node: Parent ProcessNode.
            child_node: Child ProcessNode.

        Returns:
            Finding dict if a rule matches, else None.
        """
        for rule in self._parent_child_rules:
            if parent_name in rule["parents"] and child_name in rule["children"]:
                reason = (
                    f"Suspicious parent-child relationship: "
                    f"{parent_node.name}[{parent_node.pid}] → "
                    f"{child_node.name}[{child_node.pid}]"
                )
                self._alerts.raise_alert(
                    severity=rule["severity"],
                    category=rule["category"],
                    process_name=child_node.name,
                    pid=child_node.pid,
                    reason=reason,
                    recommendation=rule["recommendation"],
                    exe_path=child_node.exe_path,
                    rule_id=rule["id"],
                    mitre_technique=rule["mitre"],
                    details={
                        "parent_pid": parent_node.pid,
                        "parent_name": parent_node.name,
                        "parent_path": parent_node.exe_path,
                        "child_pid": child_node.pid,
                        "child_name": child_node.name,
                        "child_path": child_node.exe_path,
                        "rule_name": rule["name"],
                    },
                )
                return {
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "parent_pid": parent_node.pid,
                    "parent_name": parent_node.name,
                    "child_pid": child_node.pid,
                    "child_name": child_node.name,
                    "reason": reason,
                    "mitre": rule["mitre"],
                }
        return None

    def get_process_chain(self, pid: int) -> list[dict]:
        """
        Get the full ancestry chain for a given PID.

        Args:
            pid: Process ID to trace upward.

        Returns:
            List of ancestor dicts from oldest to the given process.
        """
        chain: list[dict] = []
        with self._lock:
            node = self._tree_cache.get(pid)

        while node:
            chain.append({
                "pid": node.pid,
                "name": node.name,
                "exe_path": node.exe_path,
            })
            node = node.parent

        chain.reverse()
        return chain

    def get_process_descendants(self, pid: int) -> list[dict]:
        """
        Get all descendant processes for a given PID.

        Args:
            pid: Root process ID.

        Returns:
            Flat list of all descendant process dicts.
        """
        descendants: list[dict] = []
        with self._lock:
            root = self._tree_cache.get(pid)

        if not root:
            return descendants

        stack = list(root.children)
        while stack:
            node = stack.pop()
            descendants.append({
                "pid": node.pid,
                "name": node.name,
                "exe_path": node.exe_path,
            })
            stack.extend(node.children)

        return descendants

    def get_tree_as_text(self, node: Optional[ProcessNode] = None, indent: int = 0) -> str:
        """
        Render a process tree as indented text for display.

        Args:
            node: Root node; if None, uses all system roots.
            indent: Current indentation level.

        Returns:
            Multi-line string representation of the tree.
        """
        lines: list[str] = []

        if node is None:
            with self._lock:
                roots = list(self._root_nodes)
            for root in roots:
                lines.append(self.get_tree_as_text(root, 0))
            return "\n".join(lines)

        prefix = "  " * indent + ("└── " if indent > 0 else "")
        lines.append(f"{prefix}{node.name} [{node.pid}]")
        for child in node.children:
            lines.append(self.get_tree_as_text(child, indent + 1))
        return "\n".join(lines)

    def get_flat_relationships(self) -> list[dict]:
        """
        Return a flat list of all parent-child pairs in the process tree.

        Returns:
            List of dicts with parent/child information.
        """
        pairs: list[dict] = []
        with self._lock:
            nodes = dict(self._tree_cache)

        for node in nodes.values():
            for child in node.children:
                pairs.append({
                    "parent_pid": node.pid,
                    "parent_name": node.name,
                    "child_pid": child.pid,
                    "child_name": child.name,
                })
        return pairs
