"""
Base Analyzer Interface
Defines the common interface for all app analyzers.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field


@dataclass
class AnalysisResult:
    """Result of an app analysis."""

    success: bool
    platform: str  # 'ios' or 'android'
    packages: List[str] = field(default_factory=list)
    frameworks: List[str] = field(default_factory=list)
    native_libs: List[str] = field(default_factory=list)
    files: List[str] = field(default_factory=list)
    classes: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)
    error: Optional[str] = None

    def __repr__(self):
        if self.success:
            return (f"AnalysisResult(platform='{self.platform}', "
                    f"packages={len(self.packages)}, "
                    f"frameworks={len(self.frameworks)}, "
                    f"native_libs={len(self.native_libs)})")
        else:
            return f"AnalysisResult(success=False, error='{self.error}')"


class BaseAnalyzer(ABC):
    """Base class for app analyzers."""

    def __init__(self):
        """Initialize analyzer."""
        pass

    @abstractmethod
    def analyze(self, file_path: str, progress_callback: Optional[Callable[[str], None]] = None) -> AnalysisResult:
        """
        Analyze an app file.

        Args:
            file_path: Path to app file (APK or IPA)
            progress_callback: Optional callback function to report progress

        Returns:
            AnalysisResult object
        """
        pass

    def _report_progress(self, message: str, progress_callback: Optional[Callable[[str], None]] = None):
        """
        Report progress to callback if provided.

        Args:
            message: Progress message
            progress_callback: Optional callback function
        """
        if progress_callback:
            progress_callback(message)

    @staticmethod
    def _normalize_package_name(name: str) -> str:
        """
        Normalize package/framework name for comparison.

        Args:
            name: Package or framework name

        Returns:
            Normalized name (lowercase, stripped)
        """
        return name.strip().lower()

    @staticmethod
    def _extract_base_package(package: str) -> str:
        """
        Extract base package from full package name.

        Example: com.example.app.ui -> com.example

        Args:
            package: Full package name

        Returns:
            Base package name
        """
        parts = package.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[:2])
        return package
