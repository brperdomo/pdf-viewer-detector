"""
IPA Analyzer
Analyzes iOS IPA files to extract frameworks and dependencies.
"""

import os
import zipfile
import plistlib
import re
from pathlib import Path
from typing import Optional, Callable, Set, List, Dict

from .base import BaseAnalyzer, AnalysisResult


class IPAAnalyzer(BaseAnalyzer):
    """Analyze iOS IPA files."""

    def __init__(self):
        """Initialize IPA analyzer."""
        super().__init__()

    def analyze(self, file_path: str, progress_callback: Optional[Callable[[str], None]] = None) -> AnalysisResult:
        """
        Analyze an IPA file.

        Args:
            file_path: Path to IPA file
            progress_callback: Optional callback for progress updates

        Returns:
            AnalysisResult object
        """
        self._report_progress("Loading IPA file...", progress_callback)

        try:
            result = AnalysisResult(
                success=True,
                platform='ios'
            )

            # Extract IPA contents
            self._report_progress("Extracting IPA contents...", progress_callback)

            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                # Find the .app directory
                app_dir = self._find_app_directory(zip_ref)

                if not app_dir:
                    return AnalysisResult(
                        success=False,
                        platform='ios',
                        error="Could not find .app directory in IPA"
                    )

                self._report_progress(f"Found app directory: {app_dir}", progress_callback)

                # Extract metadata from Info.plist
                self._report_progress("Reading Info.plist...", progress_callback)
                metadata = self._extract_info_plist(zip_ref, app_dir)
                result.metadata = metadata

                # Extract frameworks
                self._report_progress("Extracting frameworks...", progress_callback)
                frameworks = self._extract_frameworks(zip_ref, app_dir)
                result.frameworks = sorted([str(f) for f in frameworks])

                # Extract imported frameworks (from binary if possible)
                self._report_progress("Analyzing binary imports...", progress_callback)
                imports = self._extract_binary_imports(zip_ref, app_dir, metadata.get('bundle_id', ''))
                result.imports = sorted([str(i) for i in imports])

                # Extract files (libraries, resources)
                self._report_progress("Scanning for library files...", progress_callback)
                files = self._extract_library_files(zip_ref, app_dir)
                result.files = sorted([str(f) for f in files])

                self._report_progress("Analysis complete!", progress_callback)
                return result

        except Exception as e:
            return AnalysisResult(
                success=False,
                platform='ios',
                error=f"Failed to analyze IPA: {str(e)}"
            )

    def _find_app_directory(self, zip_ref: zipfile.ZipFile) -> Optional[str]:
        """
        Find the .app directory in the IPA.

        Args:
            zip_ref: ZipFile reference

        Returns:
            Path to .app directory or None
        """
        for name in zip_ref.namelist():
            if '.app/' in name:
                # Extract the .app directory path
                parts = name.split('.app/')
                if len(parts) >= 1:
                    return parts[0] + '.app/'
        return None

    def _extract_info_plist(self, zip_ref: zipfile.ZipFile, app_dir: str) -> Dict:
        """
        Extract metadata from Info.plist.

        Args:
            zip_ref: ZipFile reference
            app_dir: Path to .app directory

        Returns:
            Dictionary with app metadata
        """
        metadata = {}

        try:
            info_plist_path = f"{app_dir}Info.plist"

            if info_plist_path in zip_ref.namelist():
                with zip_ref.open(info_plist_path) as plist_file:
                    plist_data = plistlib.load(plist_file)

                    metadata['app_name'] = str(plist_data.get('CFBundleDisplayName',
                                                          plist_data.get('CFBundleName', 'Unknown')))
                    metadata['bundle_id'] = str(plist_data.get('CFBundleIdentifier', 'Unknown'))
                    metadata['version'] = str(plist_data.get('CFBundleShortVersionString', 'Unknown'))
                    metadata['build'] = str(plist_data.get('CFBundleVersion', 'Unknown'))
                    metadata['min_os_version'] = str(plist_data.get('MinimumOSVersion', 'Unknown'))
                    platforms = plist_data.get('CFBundleSupportedPlatforms', [])
                    metadata['supported_platforms'] = [str(p) for p in platforms] if platforms else []

                    # Extract executable name
                    metadata['executable'] = str(plist_data.get('CFBundleExecutable', ''))

        except Exception:
            pass

        return metadata

    def _extract_frameworks(self, zip_ref: zipfile.ZipFile, app_dir: str) -> Set[str]:
        """
        Extract framework names from Frameworks directory.

        Args:
            zip_ref: ZipFile reference
            app_dir: Path to .app directory

        Returns:
            Set of framework names
        """
        frameworks = set()
        frameworks_dir = f"{app_dir}Frameworks/"

        try:
            for name in zip_ref.namelist():
                if name.startswith(frameworks_dir):
                    # Extract framework name
                    # Format: Payload/App.app/Frameworks/FrameworkName.framework/...
                    relative_path = name[len(frameworks_dir):]

                    if relative_path and '/' in relative_path:
                        framework_name = relative_path.split('/')[0]

                        if framework_name.endswith('.framework'):
                            # Remove .framework extension
                            framework_name = framework_name[:-10]
                            frameworks.add(framework_name)

        except Exception:
            pass

        # Add common iOS frameworks that are likely present
        # These are system frameworks that might be used
        system_frameworks = []

        # Check if PDFKit or CoreGraphics are likely used based on file content
        for name in zip_ref.namelist():
            if 'pdf' in name.lower():
                system_frameworks.extend(['PDFKit', 'CoreGraphics'])
                break

        frameworks.update(system_frameworks)

        return frameworks

    def _extract_binary_imports(self, zip_ref: zipfile.ZipFile, app_dir: str, bundle_id: str) -> Set[str]:
        """
        Extract imported frameworks from the main binary.

        Args:
            zip_ref: ZipFile reference
            app_dir: Path to .app directory
            bundle_id: Bundle identifier

        Returns:
            Set of imported framework names
        """
        imports = set()

        try:
            # Find the main executable
            # It should be in the root of the .app directory
            executable_name = None

            # Try to find executable in Info.plist or guess from bundle_id
            for name in zip_ref.namelist():
                if name.startswith(app_dir) and not '/' in name[len(app_dir):]:
                    # File in root of .app directory
                    basename = os.path.basename(name)
                    if basename and not basename.startswith('.') and '.' not in basename:
                        executable_name = name
                        break

            if executable_name:
                # Read binary and search for framework references
                with zip_ref.open(executable_name) as binary_file:
                    # Read first few MB only to avoid memory issues
                    binary_data = binary_file.read(5 * 1024 * 1024)

                    # Convert to string (ignore errors)
                    binary_str = binary_data.decode('utf-8', errors='ignore')

                    # Search for framework patterns
                    # Look for @rpath/, framework names, etc.
                    framework_patterns = [
                        r'@rpath/([A-Za-z0-9_]+)\.framework',
                        r'/([A-Za-z0-9_]+)\.framework',
                        r'([A-Za-z0-9_]+)\.framework/\1'
                    ]

                    for pattern in framework_patterns:
                        matches = re.findall(pattern, binary_str)
                        imports.update(matches)

                    # Also search for common PDF-related strings
                    pdf_keywords = ['PDFKit', 'PDFView', 'PDFDocument', 'CGPDFDocument',
                                   'PSPDFKit', 'Foxit', 'Adobe', 'MuPDF']

                    for keyword in pdf_keywords:
                        if keyword in binary_str:
                            imports.add(keyword)

        except Exception:
            pass

        return imports

    def _extract_library_files(self, zip_ref: zipfile.ZipFile, app_dir: str) -> Set[str]:
        """
        Extract library files and interesting resources.

        Args:
            zip_ref: ZipFile reference
            app_dir: Path to .app directory

        Returns:
            Set of file names
        """
        files = set()
        keywords = ['pdf', 'mupdf', 'foxit', 'pspdfkit', 'adobe', 'rpsdk']

        try:
            for name in zip_ref.namelist():
                if name.startswith(app_dir):
                    basename = os.path.basename(name).lower()

                    # Look for files with PDF-related keywords
                    if any(keyword in basename for keyword in keywords):
                        files.add(os.path.basename(name))

                    # Look for .dylib files (dynamic libraries)
                    if basename.endswith('.dylib'):
                        files.add(os.path.basename(name))

                    # Look for .a files (static libraries)
                    if basename.endswith('.a'):
                        files.add(os.path.basename(name))

        except Exception:
            pass

        return files

    def analyze_from_directory(self, directory_path: str,
                               progress_callback: Optional[Callable[[str], None]] = None) -> AnalysisResult:
        """
        Analyze an extracted IPA directory.

        Args:
            directory_path: Path to extracted IPA directory
            progress_callback: Optional callback for progress updates

        Returns:
            AnalysisResult object
        """
        # This method can be used if the IPA is already extracted
        # Implementation would be similar to analyze() but working with file system
        # instead of zip file
        pass
