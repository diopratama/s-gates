from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AdapterResult:
    scanner_name: str
    version: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    dependencies: List[Dict[str, Any]] = field(default_factory=list)
    raw_report: Dict[str, Any] = field(default_factory=dict)
    execution_time_seconds: float = 0.0
    success: bool = True
    error_message: Optional[str] = None


class BaseScannerAdapter(ABC):
    @abstractmethod
    def is_available(self) -> bool:
        """Checks if scanner CLI executable exists in system PATH."""
        pass

    @abstractmethod
    def get_version(self) -> str:
        """Returns version string or 'not-installed'."""
        pass

    @abstractmethod
    def scan(self, target_dir: str, timeout_seconds: int = 60) -> AdapterResult:
        """Runs the scanner on target_dir and returns structured findings and dependencies."""
        pass

