"""
APK Analyzer
Analyzes Android APK files to extract dependencies and libraries.
"""

import os
import zipfile
from pathlib import Path
from typing import Optional, Callable, Set, List, Dict
from collections import defaultdict

from androguard.core.apk import APK
from androguard.core.dex import DEX

from .base import BaseAnalyzer, AnalysisResult


class APKAnalyzer(BaseAnalyzer):
    """Analyze Android APK files."""

    def __init__(self):
        """Initialize APK analyzer."""
        super().__init__()

    def analyze(self, file_path: str, progress_callback: Optional[Callable[[str], None]] = None) -> AnalysisResult:
        """
        Analyze an APK file.

        Args:
            file_path: Path to APK file
            progress_callback: Optional callback for progress updates

        Returns:
            AnalysisResult object
        """
        self._report_progress("Loading APK file...", progress_callback)

        try:
            # Load APK
            apk = APK(file_path)

            result = AnalysisResult(
                success=True,
                platform='android'
            )

            # Extract package name
            package_name = apk.get_package()
            result.metadata['package_name'] = package_name

            # Extract app metadata
            self._report_progress("Extracting app metadata...", progress_callback)
            result.metadata['app_name'] = apk.get_app_name()
            result.metadata['version_name'] = str(apk.get_androidversion_name()) if apk.get_androidversion_name() else 'Unknown'
            result.metadata['version_code'] = str(apk.get_androidversion_code()) if apk.get_androidversion_code() else 'Unknown'
            result.metadata['min_sdk'] = str(apk.get_min_sdk_version()) if apk.get_min_sdk_version() else 'Unknown'
            result.metadata['target_sdk'] = str(apk.get_target_sdk_version()) if apk.get_target_sdk_version() else 'Unknown'

            # Extract APK file size
            result.metadata['apk_size'] = os.path.getsize(file_path)
            result.metadata['apk_size_formatted'] = self._format_size(result.metadata['apk_size'])

            # Extract permissions
            self._report_progress("Extracting permissions...", progress_callback)
            permissions = apk.get_permissions()
            result.metadata['permissions'] = [str(p) for p in permissions] if permissions else []
            result.metadata['permissions_count'] = len(result.metadata['permissions'])

            # Extract hardware features
            self._report_progress("Extracting hardware features...", progress_callback)
            features = apk.get_features()
            result.metadata['hardware_features'] = [str(f) for f in features] if features else []
            result.metadata['features_count'] = len(result.metadata['hardware_features'])

            # Analyze libraries and dependencies
            self._report_progress("Analyzing dependencies...", progress_callback)

            # 1. Extract packages from DEX files with class counts
            packages, package_class_counts = self._extract_packages_from_dex(apk, progress_callback)
            result.packages = sorted([str(p) for p in packages])
            result.metadata['package_class_counts'] = package_class_counts

            # 2. Extract native libraries with details (architecture, size)
            self._report_progress("Extracting native libraries...", progress_callback)
            native_libs_detailed = self._extract_native_libraries_detailed(file_path)
            result.metadata['native_libs_detailed'] = native_libs_detailed
            result.native_libs = sorted([lib['name'] for lib in native_libs_detailed])

            # 3. Extract JAR files
            self._report_progress("Scanning for JAR files...", progress_callback)
            jar_files = self._extract_jar_files(file_path)
            result.files = sorted([str(f) for f in jar_files])

            # 4. Extract classes
            self._report_progress("Extracting class names...", progress_callback)
            classes = self._extract_classes(apk)
            result.classes = sorted([str(c) for c in classes])

            # 5. Count assets and resources
            self._report_progress("Counting assets and resources...", progress_callback)
            assets_info, resources_info = self._count_assets_and_resources(file_path)
            result.metadata['assets'] = assets_info
            result.metadata['resources'] = resources_info

            self._report_progress("Analysis complete!", progress_callback)
            return result

        except Exception as e:
            return AnalysisResult(
                success=False,
                platform='android',
                error=f"Failed to analyze APK: {str(e)}"
            )

    def _extract_packages_from_dex(self, apk: APK, progress_callback: Optional[Callable[[str], None]] = None) -> tuple[Set[str], Dict[str, int]]:
        """
        Extract package names from DEX files with class counts.

        Args:
            apk: APK object
            progress_callback: Progress callback

        Returns:
            Tuple of (Set of package names, Dict of package -> class count)
        """
        packages = set()
        package_class_counts = defaultdict(int)

        try:
            # Try using DalvikVMFormat objects from APK
            dx = None
            try:
                from androguard.core.analysis.analysis import Analysis
                from androguard.core.dex import DEX

                # Get DEX objects directly (convert generator to list)
                dex_files = list(apk.get_all_dex())

                if not dex_files:
                    return packages, dict(package_class_counts)

                for idx, dex_data in enumerate(dex_files):
                    self._report_progress(f"Analyzing DEX file {idx + 1}/{len(dex_files)}...", progress_callback)

                    try:
                        dex = DEX(dex_data)

                        # Extract classes and their packages
                        for cls in dex.get_classes():
                            class_name = cls.get_name()
                            # Convert Lcom/example/Class; to com.example.Class
                            if class_name.startswith('L') and class_name.endswith(';'):
                                class_name = class_name[1:-1].replace('/', '.')

                                # Extract package name (everything before the last dot)
                                if '.' in class_name:
                                    package = '.'.join(class_name.split('.')[:-1])
                                    packages.add(package)
                                    package_class_counts[package] += 1

                                    # Also add parent packages for better matching
                                    parts = package.split('.')
                                    for i in range(2, len(parts)):
                                        parent_package = '.'.join(parts[:i])
                                        packages.add(parent_package)

                    except Exception as e:
                        self._report_progress(f"Warning: Could not parse DEX file {idx}: {str(e)}", progress_callback)
                        continue

            except Exception as e:
                pass

        except Exception as e:
            self._report_progress(f"Warning: Error extracting packages: {str(e)}", progress_callback)

        return packages, dict(package_class_counts)

    def _extract_native_libraries(self, apk_path: str) -> Set[str]:
        """
        Extract native library names from APK.

        Args:
            apk_path: Path to APK file

        Returns:
            Set of native library names
        """
        native_libs = set()

        try:
            with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                for file_name in zip_ref.namelist():
                    # Native libraries are in lib/ directory
                    if file_name.startswith('lib/') and file_name.endswith('.so'):
                        # Extract just the library name
                        lib_name = os.path.basename(file_name)
                        native_libs.add(lib_name)

        except Exception:
            pass

        return native_libs

    def _extract_native_libraries_detailed(self, apk_path: str) -> List[Dict[str, any]]:
        """
        Extract native libraries with architecture and size details.

        Args:
            apk_path: Path to APK file

        Returns:
            List of dictionaries with library details
        """
        native_libs = []

        try:
            with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                for file_info in zip_ref.filelist:
                    file_name = file_info.filename

                    # Native libraries are in lib/ directory
                    if file_name.startswith('lib/') and file_name.endswith('.so'):
                        # Extract architecture and library name
                        # Format: lib/armeabi-v7a/libfoo.so
                        parts = file_name.split('/')
                        if len(parts) >= 3:
                            arch = parts[1]
                            lib_name = parts[-1]

                            native_libs.append({
                                'name': lib_name,
                                'architecture': arch,
                                'size': file_info.file_size,
                                'size_formatted': self._format_size(file_info.file_size),
                                'path': file_name
                            })

        except Exception:
            pass

        # Sort by name, then by architecture
        return sorted(native_libs, key=lambda x: (x['name'], x['architecture']))

    def _count_assets_and_resources(self, apk_path: str) -> tuple[Dict[str, any], Dict[str, any]]:
        """
        Count assets and resources in the APK.

        Args:
            apk_path: Path to APK file

        Returns:
            Tuple of (assets info, resources info)
        """
        assets_count = 0
        assets_size = 0
        resources_count = 0
        resources_size = 0

        try:
            with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                for file_info in zip_ref.filelist:
                    file_name = file_info.filename

                    if file_name.startswith('assets/'):
                        assets_count += 1
                        assets_size += file_info.file_size
                    elif file_name.startswith('res/'):
                        resources_count += 1
                        resources_size += file_info.file_size

        except Exception:
            pass

        assets_info = {
            'count': assets_count,
            'size': assets_size,
            'size_formatted': self._format_size(assets_size)
        }

        resources_info = {
            'count': resources_count,
            'size': resources_size,
            'size_formatted': self._format_size(resources_size)
        }

        return assets_info, resources_info

    def _format_size(self, size_bytes: int) -> str:
        """
        Format size in bytes to human-readable string.

        Args:
            size_bytes: Size in bytes

        Returns:
            Formatted size string
        """
        if size_bytes < 1024:
            return f"{size_bytes}B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f}K"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f}M"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.2f}G"

    def _extract_jar_files(self, apk_path: str) -> Set[str]:
        """
        Extract JAR file names from APK.

        Args:
            apk_path: Path to APK file

        Returns:
            Set of JAR file names
        """
        jar_files = set()

        try:
            with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                for file_name in zip_ref.namelist():
                    # Look for JAR files
                    if file_name.endswith('.jar'):
                        jar_files.add(os.path.basename(file_name))

        except Exception:
            pass

        return jar_files

    def _extract_classes(self, apk: APK) -> List[str]:
        """
        Extract interesting class names (limit to reasonable number).

        Args:
            apk: APK object

        Returns:
            List of class names
        """
        classes = []
        keywords = ['pdf', 'viewer', 'reader', 'document', 'page', 'render']

        try:
            dex_files = apk.get_all_dex()

            for dex_data in dex_files:
                try:
                    dex = DEX(dex_data)

                    for cls in dex.get_classes():
                        class_name = cls.get_name()

                        # Convert Lcom/example/Class; to com.example.Class
                        if class_name.startswith('L') and class_name.endswith(';'):
                            class_name = class_name[1:-1].replace('/', '.')

                            # Only keep classes with PDF-related keywords
                            if any(keyword in class_name.lower() for keyword in keywords):
                                classes.append(class_name)

                                # Limit to avoid too many results
                                if len(classes) >= 100:
                                    return classes

                except Exception:
                    continue

        except Exception:
            pass

        return classes
