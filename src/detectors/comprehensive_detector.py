"""
Comprehensive Library Detector
Detects all types of libraries and SDKs in Android and iOS apps.
"""

import json
from pathlib import Path
from typing import Dict, List
from collections import defaultdict


class ComprehensiveDetector:
    """Detect all types of libraries and SDKs."""

    def __init__(self):
        """Initialize comprehensive detector."""
        self.pdf_libraries = self._load_pdf_libraries()
        self.comprehensive_libraries = self._load_comprehensive_libraries()
        self.library_descriptions = self._load_library_descriptions()
        self.document_viewing_solutions = self._load_document_viewing_solutions()
        self.pdf_sdk_features = self._load_pdf_sdk_features()
        self.pdf_sdk_version_patterns = self._load_pdf_sdk_version_patterns()

    def _load_pdf_libraries(self) -> Dict:
        """Load PDF library signatures."""
        lib_file = Path(__file__).parent.parent.parent / 'data' / 'pdf_libraries.json'
        try:
            with open(lib_file, 'r') as f:
                return json.load(f)
        except Exception:
            return {'android_libraries': [], 'ios_libraries': []}

    def _load_comprehensive_libraries(self) -> Dict:
        """Load comprehensive library database."""
        lib_file = Path(__file__).parent.parent.parent / 'data' / 'comprehensive_libraries.json'
        try:
            with open(lib_file, 'r') as f:
                return json.load(f)
        except Exception:
            return {}

    def _load_library_descriptions(self) -> Dict:
        """Load library descriptions."""
        lib_file = Path(__file__).parent.parent.parent / 'data' / 'library_descriptions.json'
        try:
            with open(lib_file, 'r') as f:
                return json.load(f)
        except Exception:
            return {}

    def _load_document_viewing_solutions(self) -> Dict:
        """Load non-commercial document viewing solutions."""
        lib_file = Path(__file__).parent.parent.parent / 'data' / 'document_viewing_solutions.json'
        try:
            with open(lib_file, 'r') as f:
                return json.load(f)
        except Exception:
            return {'android_solutions': [], 'ios_solutions': []}

    def _load_pdf_sdk_features(self) -> Dict:
        """Load PDF SDK feature signatures."""
        lib_file = Path(__file__).parent.parent.parent / 'data' / 'pdf_sdk_features.json'
        try:
            with open(lib_file, 'r') as f:
                return json.load(f)
        except Exception:
            return {}

    def _load_pdf_sdk_version_patterns(self) -> Dict:
        """Load PDF SDK version detection patterns."""
        lib_file = Path(__file__).parent.parent.parent / 'data' / 'pdf_sdk_version_patterns.json'
        try:
            with open(lib_file, 'r') as f:
                return json.load(f)
        except Exception:
            return {'version_detection_patterns': {}}

    def detect(self, analysis_result) -> Dict:
        """
        Detect all libraries in an analysis result.

        Args:
            analysis_result: AnalysisResult object

        Returns:
            Dictionary with categorized library detections
        """
        results = {
            'pdf_libraries': [],
            'document_viewing_solutions': [],
            'google_play_services': [],
            'firebase': [],
            'androidx': [],
            'kotlin': [],
            'analytics': [],
            'crash_reporting': [],
            'networking': [],
            'ui_libraries': [],
            'dependency_injection': [],
            'social': [],
            'other': []
        }

        platform = analysis_result.platform

        if platform == 'android':
            # Detect PDF libraries (with special highlighting)
            results['pdf_libraries'] = self._detect_android_pdf_libraries(analysis_result)

            # Detect non-commercial document viewing solutions
            results['document_viewing_solutions'] = self._detect_document_viewing_solutions(analysis_result)

            # Detect comprehensive libraries
            results['google_play_services'] = self._detect_google_play_services(analysis_result)
            results['firebase'] = self._detect_firebase(analysis_result)
            results['androidx'] = self._detect_androidx(analysis_result)
            results['kotlin'] = self._detect_kotlin(analysis_result)
            results['analytics'] = self._detect_analytics(analysis_result)
            results['crash_reporting'] = self._detect_crash_reporting(analysis_result)
            results['networking'] = self._detect_networking(analysis_result)
            results['ui_libraries'] = self._detect_ui_libraries(analysis_result)
            results['dependency_injection'] = self._detect_dependency_injection(analysis_result)
            results['social'] = self._detect_social(analysis_result)

        elif platform == 'ios':
            results['pdf_libraries'] = self._detect_ios_pdf_libraries(analysis_result)
            results['document_viewing_solutions'] = self._detect_document_viewing_solutions(analysis_result)

        return results

    def _detect_android_pdf_libraries(self, analysis_result) -> List[Dict]:
        """Detect PDF libraries in Android app."""
        detected = []

        for lib in self.pdf_libraries.get('android_libraries', []):
            confidence = 0
            matched_signatures = []
            locations = []

            signatures = lib.get('signatures', {})

            # Check packages
            if 'packages' in signatures:
                for package in signatures['packages']:
                    if any(package in p for p in analysis_result.packages):
                        confidence += 40
                        matched_signatures.append(f"Package: {package}")
                        locations.append(f"Package: {package}")

            # Check files
            if 'files' in signatures:
                for file_sig in signatures['files']:
                    if any(file_sig.lower() in f.lower() for f in analysis_result.files):
                        confidence += 30
                        matched_signatures.append(f"File: {file_sig}")
                        locations.append(f"File match: {file_sig}")

            # Check native libraries
            if 'native_libs' in signatures:
                for native_lib in signatures['native_libs']:
                    if any(native_lib in nl for nl in analysis_result.native_libs):
                        confidence += 30
                        matched_signatures.append(f"Native library: {native_lib}")
                        locations.append(f"Native: {native_lib}")

            # Check classes
            if 'classes' in signatures:
                for class_name in signatures['classes']:
                    if any(class_name in c for c in analysis_result.classes):
                        confidence += 20
                        matched_signatures.append(f"Class: {class_name}")

            if confidence > 0:
                lib_info = {
                    'name': lib['name'],
                    'description': lib.get('description', ''),
                    'confidence': min(confidence, 100),
                    'matched_signatures': matched_signatures,
                    'locations': locations,
                    'is_pdf': True  # Flag for highlighting
                }

                # Detect version for this SDK
                sdk_key = self._get_sdk_key(lib['name'])
                if sdk_key:
                    version_info = self._detect_sdk_version(sdk_key, analysis_result)
                    if version_info:
                        lib_info['version'] = version_info

                    # Detect features for this SDK
                    features = self._detect_sdk_features(sdk_key, analysis_result)
                    if features:
                        lib_info['features'] = features

                detected.append(lib_info)

        return sorted(detected, key=lambda x: x['confidence'], reverse=True)

    def _detect_ios_pdf_libraries(self, analysis_result) -> List[Dict]:
        """Detect PDF libraries in iOS app."""
        detected = []

        for lib in self.pdf_libraries.get('ios_libraries', []):
            confidence = 0
            matched_signatures = []
            locations = []

            signatures = lib.get('signatures', {})

            # Check frameworks
            if 'frameworks' in signatures:
                for framework in signatures['frameworks']:
                    if any(framework in f for f in analysis_result.frameworks):
                        confidence += 40
                        matched_signatures.append(f"Framework: {framework}")
                        locations.append(f"Framework: {framework}")

            # Check files
            if 'files' in signatures:
                for file_sig in signatures['files']:
                    if any(file_sig.lower() in f.lower() for f in analysis_result.files):
                        confidence += 30
                        matched_signatures.append(f"File: {file_sig}")

            if confidence > 0:
                detected.append({
                    'name': lib['name'],
                    'description': lib.get('description', ''),
                    'confidence': min(confidence, 100),
                    'matched_signatures': matched_signatures,
                    'locations': locations,
                    'is_pdf': True
                })

        return sorted(detected, key=lambda x: x['confidence'], reverse=True)

    def _detect_document_viewing_solutions(self, analysis_result) -> List[Dict]:
        """Detect non-commercial document viewing solutions."""
        detected = []
        platform = analysis_result.platform

        solutions = self.document_viewing_solutions.get(
            'android_solutions' if platform == 'android' else 'ios_solutions',
            []
        )

        for solution in solutions:
            found = False
            matched = []

            signatures = solution.get('signatures', {})

            # Check packages
            if 'packages' in signatures:
                for package in signatures['packages']:
                    if any(package in p for p in analysis_result.packages):
                        found = True
                        matched.append(f"Package: {package}")

            # Check classes
            if 'classes' in signatures:
                for class_name in signatures['classes']:
                    if any(class_name in c for c in analysis_result.classes):
                        found = True
                        matched.append(f"Class: {class_name}")

            # Check files
            if 'files' in signatures:
                for file_sig in signatures['files']:
                    if any(file_sig.lower() in f.lower() for f in analysis_result.files):
                        found = True
                        matched.append(f"File: {file_sig}")

            # Check frameworks (iOS)
            if platform == 'ios' and 'frameworks' in signatures:
                for framework in signatures['frameworks']:
                    if any(framework in f for f in analysis_result.frameworks):
                        found = True
                        matched.append(f"Framework: {framework}")

            if found:
                detected.append({
                    'name': solution['name'],
                    'description': solution['description'],
                    'type': solution['type'],
                    'matched': matched,
                    'note': solution.get('note', '')
                })

        return detected

    def _detect_google_play_services(self, analysis_result) -> List[Dict]:
        """Detect Google Play Services libraries."""
        detected = []
        detected_packages = set()

        for lib in self.comprehensive_libraries.get('google_play_services', []):
            package = lib['package']
            if any(package in p for p in analysis_result.packages):
                if package not in detected_packages:
                    detected_packages.add(package)

                    # Try to extract version from metadata
                    version = self._extract_version(package, analysis_result)

                    # Get description
                    description = self.library_descriptions.get('google_play_services', {}).get(lib['name'], '')

                    detected.append({
                        'name': lib['name'],
                        'package': package,
                        'category': lib['category'],
                        'version': version,
                        'description': description
                    })

        return sorted(detected, key=lambda x: x['name'])

    def _detect_firebase(self, analysis_result) -> List[Dict]:
        """Detect Firebase libraries."""
        detected = []
        detected_packages = set()

        for lib in self.comprehensive_libraries.get('firebase', []):
            package = lib['package']
            if any(package in p for p in analysis_result.packages):
                if package not in detected_packages:
                    detected_packages.add(package)
                    version = self._extract_version(package, analysis_result)
                    description = self.library_descriptions.get('firebase', {}).get(lib['name'], '')

                    detected.append({
                        'name': lib['name'],
                        'package': package,
                        'category': lib['category'],
                        'version': version,
                        'description': description
                    })

        return sorted(detected, key=lambda x: x['name'])

    def _detect_androidx(self, analysis_result) -> List[Dict]:
        """Detect AndroidX/Jetpack libraries."""
        detected = []
        detected_packages = set()

        for lib in self.comprehensive_libraries.get('androidx', []):
            package = lib['package']
            if any(package in p for p in analysis_result.packages):
                if package not in detected_packages:
                    detected_packages.add(package)
                    version = self._extract_version(package, analysis_result)
                    description = self.library_descriptions.get('androidx', {}).get(lib['name'], '')

                    detected.append({
                        'name': lib['name'],
                        'package': package,
                        'category': lib['category'],
                        'version': version,
                        'description': description
                    })

        return sorted(detected, key=lambda x: x['name'])

    def _detect_kotlin(self, analysis_result) -> List[Dict]:
        """Detect Kotlin libraries."""
        detected = []
        detected_packages = set()

        for lib in self.comprehensive_libraries.get('kotlin', []):
            package = lib['package']
            if any(package in p for p in analysis_result.packages):
                if package not in detected_packages:
                    detected_packages.add(package)
                    version = self._extract_version(package, analysis_result)
                    description = self.library_descriptions.get('kotlin', {}).get(lib['name'], '')

                    detected.append({
                        'name': lib['name'],
                        'package': package,
                        'category': lib['category'],
                        'version': version,
                        'description': description
                    })

        return sorted(detected, key=lambda x: x['name'])

    def _detect_analytics(self, analysis_result) -> List[Dict]:
        """Detect analytics SDKs."""
        detected = []

        for lib in self.comprehensive_libraries.get('analytics_sdks', []):
            found = False

            # Check package
            if any(lib['package'] in p for p in analysis_result.packages):
                found = True

            # Check native library if specified
            if 'native_lib' in lib and any(lib['native_lib'] in nl for nl in analysis_result.native_libs):
                found = True

            if found:
                description = self.library_descriptions.get('analytics', {}).get(lib['name'], '')
                detected.append({
                    'name': lib['name'],
                    'package': lib['package'],
                    'category': lib['category'],
                    'description': description
                })

        return sorted(detected, key=lambda x: x['name'])

    def _detect_crash_reporting(self, analysis_result) -> List[Dict]:
        """Detect crash reporting SDKs."""
        detected = []

        for lib in self.comprehensive_libraries.get('crash_reporting', []):
            found = False

            # Check package
            if any(lib['package'] in p for p in analysis_result.packages):
                found = True

            # Check native library if specified
            if 'native_lib' in lib and any(lib['native_lib'] in nl for nl in analysis_result.native_libs):
                found = True

            if found:
                description = self.library_descriptions.get('crash_reporting', {}).get(lib['name'], '')
                detected.append({
                    'name': lib['name'],
                    'package': lib['package'],
                    'category': lib['category'],
                    'description': description
                })

        return sorted(detected, key=lambda x: x['name'])

    def _detect_networking(self, analysis_result) -> List[Dict]:
        """Detect networking libraries."""
        detected = []
        detected_packages = set()

        for lib in self.comprehensive_libraries.get('networking', []):
            package = lib['package']
            if any(package in p for p in analysis_result.packages):
                if package not in detected_packages:
                    detected_packages.add(package)
                    description = self.library_descriptions.get('networking', {}).get(lib['name'], '')

                    detected.append({
                        'name': lib['name'],
                        'package': package,
                        'category': lib['category'],
                        'description': description
                    })

        return sorted(detected, key=lambda x: x['name'])

    def _detect_ui_libraries(self, analysis_result) -> List[Dict]:
        """Detect UI libraries."""
        detected = []
        detected_packages = set()

        for lib in self.comprehensive_libraries.get('ui_libraries', []):
            package = lib['package']
            if any(package in p for p in analysis_result.packages):
                if package not in detected_packages:
                    detected_packages.add(package)
                    description = self.library_descriptions.get('ui', {}).get(lib['name'], '')

                    detected.append({
                        'name': lib['name'],
                        'package': package,
                        'category': lib['category'],
                        'description': description
                    })

        return sorted(detected, key=lambda x: x['name'])

    def _detect_dependency_injection(self, analysis_result) -> List[Dict]:
        """Detect dependency injection libraries."""
        detected = []
        detected_packages = set()

        for lib in self.comprehensive_libraries.get('dependency_injection', []):
            package = lib['package']
            if any(package in p for p in analysis_result.packages):
                if package not in detected_packages:
                    detected_packages.add(package)
                    description = self.library_descriptions.get('dependency_injection', {}).get(lib['name'], '')

                    detected.append({
                        'name': lib['name'],
                        'package': package,
                        'category': lib['category'],
                        'description': description
                    })

        return sorted(detected, key=lambda x: x['name'])

    def _detect_social(self, analysis_result) -> List[Dict]:
        """Detect social SDK libraries."""
        detected = []
        detected_packages = set()

        for lib in self.comprehensive_libraries.get('social_sdks', []):
            package = lib['package']
            if any(package in p for p in analysis_result.packages):
                if package not in detected_packages:
                    detected_packages.add(package)
                    description = self.library_descriptions.get('social', {}).get(lib['name'], '')

                    detected.append({
                        'name': lib['name'],
                        'package': package,
                        'category': lib['category'],
                        'description': description
                    })

        return sorted(detected, key=lambda x: x['name'])

    def _extract_version(self, package: str, analysis_result) -> str:
        """
        Try to extract version from package names.
        This is a best-effort extraction.
        """
        # Look for version patterns in the package name
        # This is simplified - real version extraction would need more sophisticated parsing
        return "Unknown"

    def _get_sdk_key(self, sdk_name: str) -> str:
        """Map SDK name to key for feature/version detection."""
        name_lower = sdk_name.lower()
        if 'pspdfkit' in name_lower:
            return 'pspdfkit'
        elif 'apryse' in name_lower or 'pdftron' in name_lower:
            return 'apryse'
        elif 'foxit' in name_lower:
            return 'foxit'
        elif 'mupdf' in name_lower:
            return 'mupdf'
        return None

    def _detect_sdk_version(self, sdk_key: str, analysis_result) -> Dict:
        """
        Detect SDK version using patterns from version_detection_patterns.

        Returns dict with version info or None if not detected.
        """
        patterns = self.pdf_sdk_version_patterns.get('version_detection_patterns', {}).get(sdk_key, {})

        if not patterns:
            return None

        # Check for BuildConfig class
        build_config_class = f"com.{sdk_key}.BuildConfig" if sdk_key == 'pspdfkit' else None
        if sdk_key == 'apryse':
            build_config_class = "com.pdftron.BuildConfig"

        # Try to detect from class presence patterns
        # For now, we'll look for version-indicating classes
        version_info = {
            'detected': False,
            'method': 'Class pattern analysis'
        }

        # Check if key classes exist that indicate recent versions
        if sdk_key == 'pspdfkit':
            # Check for newer features to estimate version
            has_instant = any('com.pspdfkit.instant' in p for p in analysis_result.packages)
            has_measurement = any('MeasurementAnnotation' in c for c in analysis_result.classes)

            if has_measurement:
                version_info['version'] = '2024.x+'
                version_info['status'] = 'Recent'
                version_info['detected'] = True
            elif has_instant:
                version_info['version'] = '2023.x+'
                version_info['status'] = 'Moderate'
                version_info['detected'] = True
            else:
                version_info['version'] = 'Unknown (pre-2023?)'
                version_info['status'] = 'Potentially Outdated'
                version_info['detected'] = True

        return version_info if version_info['detected'] else None

    def _detect_sdk_features(self, sdk_key: str, analysis_result) -> List[Dict]:
        """
        Detect which features of an SDK are being used.

        Returns list of detected features with details.
        """
        features_config = self.pdf_sdk_features.get(sdk_key, {}).get('features', {})

        if not features_config:
            return []

        detected_features = []

        for feature_key, feature_info in features_config.items():
            feature_found = False
            evidence = []

            signatures = feature_info.get('signatures', {})

            # Check packages
            if 'packages' in signatures:
                for package in signatures['packages']:
                    if any(package in p for p in analysis_result.packages):
                        feature_found = True
                        evidence.append(f"Package: {package}")

            # Check classes
            if 'classes' in signatures:
                for class_name in signatures['classes']:
                    if any(class_name in c for c in analysis_result.classes):
                        feature_found = True
                        evidence.append(f"Class: {class_name}")

            if feature_found:
                detected_features.append({
                    'name': feature_info['name'],
                    'description': feature_info['description'],
                    'tier': feature_info.get('tier', 'standard'),
                    'evidence': evidence[:3]  # Limit to 3 pieces of evidence
                })

        return detected_features
