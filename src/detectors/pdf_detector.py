"""
PDF Detector
Detects PDF libraries in analyzed apps.
"""

import json
from pathlib import Path
from typing import List, Dict, Set
from dataclasses import dataclass, field

from ..analyzers.base import AnalysisResult


@dataclass
class DetectedLibrary:
    """Represents a detected PDF library."""

    name: str
    description: str
    confidence: float
    detection_methods: List[str] = field(default_factory=list)
    matched_signatures: List[str] = field(default_factory=list)
    locations: List[str] = field(default_factory=list)

    def __repr__(self):
        return f"DetectedLibrary(name='{self.name}', confidence={self.confidence:.1f}%)"


class PDFDetector:
    """Detect PDF libraries in app analysis results."""

    def __init__(self, signatures_path: str = None):
        """
        Initialize PDF detector.

        Args:
            signatures_path: Path to PDF library signatures JSON file
        """
        if signatures_path is None:
            # Default to data/pdf_libraries.json relative to this file
            current_dir = Path(__file__).parent.parent.parent
            signatures_path = current_dir / 'data' / 'pdf_libraries.json'

        self.signatures_path = Path(signatures_path)
        self.signatures = self._load_signatures()

    def _load_signatures(self) -> Dict:
        """Load PDF library signatures from JSON file."""
        try:
            with open(self.signatures_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            raise RuntimeError(f"Failed to load signatures: {str(e)}")

    def detect(self, analysis_result: AnalysisResult) -> List[DetectedLibrary]:
        """
        Detect PDF libraries in analysis result.

        Args:
            analysis_result: Result from app analyzer

        Returns:
            List of detected PDF libraries, sorted by confidence
        """
        if not analysis_result.success:
            return []

        detected = []

        # Get the appropriate library signatures based on platform
        if analysis_result.platform == 'ios':
            libraries = self.signatures.get('ios_libraries', [])
        elif analysis_result.platform == 'android':
            libraries = self.signatures.get('android_libraries', [])
        else:
            return []

        # Check each library signature
        for library in libraries:
            result = self._check_library(library, analysis_result)
            if result:
                detected.append(result)

        # Sort by confidence (descending)
        detected.sort(key=lambda x: x.confidence, reverse=True)

        return detected

    def _check_library(self, library: Dict, analysis_result: AnalysisResult) -> DetectedLibrary:
        """
        Check if a library matches the analysis result.

        Args:
            library: Library signature dictionary
            analysis_result: Analysis result

        Returns:
            DetectedLibrary if matches found, None otherwise
        """
        signatures = library.get('signatures', {})
        confidence_weight = library.get('confidence_weight', 50)

        detection_methods = []
        matched_signatures = []
        locations = []
        total_matches = 0
        max_possible_matches = 0

        # Check packages (Android)
        if 'packages' in signatures:
            max_possible_matches += 1
            package_matches = self._check_packages(
                signatures['packages'],
                analysis_result.packages
            )
            if package_matches:
                total_matches += 1
                detection_methods.append('Package name')
                matched_signatures.extend(package_matches['matches'])
                locations.extend(package_matches['locations'])

        # Check frameworks (iOS)
        if 'frameworks' in signatures:
            max_possible_matches += 1
            framework_matches = self._check_items(
                signatures['frameworks'],
                analysis_result.frameworks
            )
            if framework_matches:
                total_matches += 1
                detection_methods.append('Framework')
                matched_signatures.extend(framework_matches['matches'])
                locations.extend(framework_matches['locations'])

        # Check imports (iOS)
        if 'imports' in signatures:
            max_possible_matches += 1
            import_matches = self._check_items(
                signatures['imports'],
                analysis_result.imports
            )
            if import_matches:
                total_matches += 1
                detection_methods.append('Import statement')
                matched_signatures.extend(import_matches['matches'])
                locations.extend(import_matches['locations'])

        # Check native libraries
        if 'native_libs' in signatures:
            max_possible_matches += 1
            native_matches = self._check_items(
                signatures['native_libs'],
                analysis_result.native_libs
            )
            if native_matches:
                total_matches += 1
                detection_methods.append('Native library')
                matched_signatures.extend(native_matches['matches'])
                locations.extend(native_matches['locations'])

        # Check files
        if 'files' in signatures:
            max_possible_matches += 1
            file_matches = self._check_files(
                signatures['files'],
                analysis_result.files
            )
            if file_matches:
                total_matches += 1
                detection_methods.append('File name')
                matched_signatures.extend(file_matches['matches'])
                locations.extend(file_matches['locations'])

        # Check classes
        if 'classes' in signatures:
            max_possible_matches += 1
            class_matches = self._check_items(
                signatures['classes'],
                analysis_result.classes
            )
            if class_matches:
                total_matches += 1
                detection_methods.append('Class name')
                matched_signatures.extend(class_matches['matches'])
                locations.extend(class_matches['locations'])

        # Calculate confidence
        if total_matches == 0:
            return None

        # Confidence is based on:
        # 1. Percentage of signature types matched
        # 2. Base confidence weight from signature database
        match_ratio = total_matches / max_possible_matches if max_possible_matches > 0 else 0
        confidence = match_ratio * confidence_weight

        return DetectedLibrary(
            name=library['name'],
            description=library.get('description', ''),
            confidence=confidence,
            detection_methods=detection_methods,
            matched_signatures=list(set(matched_signatures)),  # Remove duplicates
            locations=list(set(locations))
        )

    def _check_packages(self, signature_packages: List[str], app_packages: List[str]) -> Dict:
        """Check if any signature packages match app packages."""
        matches = []
        locations = []

        # Ensure all items are strings
        signature_packages_lower = [str(p).lower() for p in signature_packages]
        app_packages_lower = [str(p).lower() for p in app_packages]

        for sig_pkg in signature_packages:
            sig_pkg_lower = str(sig_pkg).lower()

            # Check for exact match
            if sig_pkg_lower in app_packages_lower:
                matches.append(str(sig_pkg))
                idx = app_packages_lower.index(sig_pkg_lower)
                locations.append(f"Package: {str(app_packages[idx])}")
                continue

            # Check for partial match (signature is prefix of app package)
            for app_pkg in app_packages:
                if str(app_pkg).lower().startswith(sig_pkg_lower):
                    matches.append(str(sig_pkg))
                    locations.append(f"Package: {str(app_pkg)}")
                    break

        if matches:
            return {'matches': matches, 'locations': locations}
        return None

    def _check_items(self, signature_items: List[str], app_items: List[str]) -> Dict:
        """Check if any signature items match app items (exact or partial)."""
        matches = []
        locations = []

        # Ensure all items are strings
        signature_items_lower = [str(item).lower() for item in signature_items]
        app_items_lower = [str(item).lower() for item in app_items]

        for sig_item in signature_items:
            sig_item_lower = str(sig_item).lower()

            # Check for exact match
            if sig_item_lower in app_items_lower:
                matches.append(str(sig_item))
                idx = app_items_lower.index(sig_item_lower)
                locations.append(str(app_items[idx]))
                continue

            # Check for partial match
            for app_item in app_items:
                app_item_str = str(app_item)
                if sig_item_lower in app_item_str.lower() or app_item_str.lower() in sig_item_lower:
                    matches.append(str(sig_item))
                    locations.append(app_item_str)
                    break

        if matches:
            return {'matches': matches, 'locations': locations}
        return None

    def _check_files(self, signature_files: List[str], app_files: List[str]) -> Dict:
        """Check if any signature file patterns match app files."""
        matches = []
        locations = []

        for sig_file in signature_files:
            sig_file_lower = str(sig_file).lower()

            for app_file in app_files:
                app_file_lower = str(app_file).lower()

                # Check if signature is contained in file name
                if sig_file_lower in app_file_lower:
                    matches.append(str(sig_file))
                    locations.append(f"File: {str(app_file)}")
                    break

        if matches:
            return {'matches': matches, 'locations': locations}
        return None

    def generate_report(self, detected_libraries: List[DetectedLibrary]) -> str:
        """
        Generate a text report of detected libraries.

        Args:
            detected_libraries: List of detected libraries

        Returns:
            Formatted text report
        """
        if not detected_libraries:
            return "No PDF libraries detected."

        report_lines = []
        report_lines.append(f"Detected {len(detected_libraries)} PDF library/libraries:\n")

        for idx, lib in enumerate(detected_libraries, 1):
            report_lines.append(f"{idx}. {lib.name}")
            report_lines.append(f"   Description: {lib.description}")
            report_lines.append(f"   Confidence: {lib.confidence:.1f}%")
            report_lines.append(f"   Detection Methods: {', '.join(lib.detection_methods)}")

            if lib.matched_signatures:
                report_lines.append(f"   Matched Signatures: {', '.join(lib.matched_signatures)}")

            if lib.locations:
                report_lines.append(f"   Locations:")
                for location in lib.locations[:5]:  # Limit to first 5
                    report_lines.append(f"     - {location}")
                if len(lib.locations) > 5:
                    report_lines.append(f"     ... and {len(lib.locations) - 5} more")

            report_lines.append("")

        return "\n".join(report_lines)
