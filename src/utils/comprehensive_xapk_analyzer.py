"""
Comprehensive XAPK Analyzer
Analyzes ALL APKs in an XAPK (base + all splits) and combines results.
"""

import os
import json
import zipfile
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Set, Optional
from collections import defaultdict


class ComprehensiveXAPKAnalyzer:
    """Analyze all APKs in an XAPK file comprehensively."""

    @staticmethod
    def extract_all_apks(xapk_path: str, output_dir: Optional[str] = None) -> Dict:
        """
        Extract ALL APKs from XAPK and categorize them.

        Args:
            xapk_path: Path to XAPK file
            output_dir: Optional directory to extract to

        Returns:
            Dictionary with extraction results
        """
        try:
            if output_dir is None:
                output_dir = tempfile.mkdtemp(prefix='xapk_comprehensive_')
            else:
                os.makedirs(output_dir, exist_ok=True)

            result = {
                'success': True,
                'output_dir': output_dir,
                'base_apk': None,
                'arch_apks': {},  # architecture -> apk_path
                'config_apks': [],  # density, language, etc.
                'manifest': None,
                'warnings': [],
                'all_apks': []
            }

            # Extract XAPK
            with zipfile.ZipFile(xapk_path, 'r') as zip_ref:
                zip_ref.extractall(output_dir)

            # Read manifest
            manifest_path = os.path.join(output_dir, 'manifest.json')
            if os.path.exists(manifest_path):
                with open(manifest_path, 'r') as f:
                    result['manifest'] = json.load(f)

            # Categorize all APKs
            for file in os.listdir(output_dir):
                if not file.endswith('.apk'):
                    continue

                full_path = os.path.join(output_dir, file)
                result['all_apks'].append(file)

                # Categorize by filename
                if 'base' in file.lower() or file == f"{result['manifest'].get('package_name', '')}.apk":
                    result['base_apk'] = full_path
                elif 'arm64' in file.lower() or 'arm64-v8a' in file.lower():
                    result['arch_apks']['arm64-v8a'] = full_path
                elif 'armeabi' in file.lower() or 'armeabi-v7a' in file.lower():
                    result['arch_apks']['armeabi-v7a'] = full_path
                elif 'x86_64' in file.lower():
                    result['arch_apks']['x86_64'] = full_path
                elif 'x86' in file.lower():
                    result['arch_apks']['x86'] = full_path
                else:
                    result['config_apks'].append(full_path)

            # Check for missing critical architectures
            if not result['arch_apks'].get('arm64-v8a') and not result['arch_apks'].get('armeabi-v7a'):
                result['warnings'].append(
                    "⚠️  WARNING: No ARM architecture APKs found! This XAPK appears incomplete. "
                    "Native libraries (including PDF SDKs) would be in ARM APKs. "
                    "Only found: " + ", ".join(result['arch_apks'].keys() or ['none'])
                )

            if not result['base_apk']:
                result['success'] = False
                result['warnings'].append("❌ ERROR: No base APK found in XAPK")

            return result

        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'warnings': [f"Failed to extract XAPK: {str(e)}"]
            }

    @staticmethod
    def merge_analysis_results(base_result, arch_results: Dict) -> Dict:
        """
        Merge analysis results from base APK and architecture splits.

        Args:
            base_result: AnalysisResult from base APK
            arch_results: Dict of architecture -> AnalysisResult

        Returns:
            Merged analysis data
        """
        # Start with base result
        merged = {
            'packages': set(base_result.packages) if base_result.packages else set(),
            'classes': set(base_result.classes) if base_result.classes else set(),
            'files': set(base_result.files) if base_result.files else set(),
            'native_libs': set(base_result.native_libs) if base_result.native_libs else set(),
            'permissions': base_result.metadata.get('permissions', []),
            'metadata': base_result.metadata.copy(),
            'native_libs_detailed': [],
            'analyzed_splits': ['base']
        }

        # Merge architecture splits
        for arch, result in arch_results.items():
            merged['analyzed_splits'].append(arch)

            # Merge native libraries (most important for PDF detection)
            if hasattr(result, 'native_libs') and result.native_libs:
                merged['native_libs'].update(result.native_libs)

            # Merge native_libs_detailed
            if 'native_libs_detailed' in result.metadata:
                merged['native_libs_detailed'].extend(result.metadata['native_libs_detailed'])

            # Merge packages (some might be architecture-specific)
            if hasattr(result, 'packages') and result.packages:
                merged['packages'].update(result.packages)

        # Update metadata with merged info
        merged['metadata']['native_libs_detailed'] = merged['native_libs_detailed']
        merged['metadata']['xapk_splits_analyzed'] = merged['analyzed_splits']
        merged['metadata']['total_native_libs'] = len(merged['native_libs_detailed'])

        return merged

    @staticmethod
    def create_analysis_summary(extraction_result: Dict) -> str:
        """
        Create a human-readable summary of what was analyzed.

        Args:
            extraction_result: Result from extract_all_apks

        Returns:
            Summary string
        """
        lines = []
        lines.append("=" * 80)
        lines.append("XAPK ANALYSIS BREAKDOWN")
        lines.append("=" * 80)

        if extraction_result.get('manifest'):
            manifest = extraction_result['manifest']
            lines.append(f"Package: {manifest.get('package_name', 'Unknown')}")
            lines.append(f"Version: {manifest.get('version_name', 'Unknown')}")
            lines.append(f"Total Size: {manifest.get('total_size', 0) / (1024*1024):.1f}M")
            lines.append("")

        lines.append("APKs IN THIS XAPK:")
        lines.append("-" * 80)

        if extraction_result.get('base_apk'):
            lines.append(f"✅ Base APK: {os.path.basename(extraction_result['base_apk'])}")
        else:
            lines.append("❌ Base APK: NOT FOUND")

        if extraction_result.get('arch_apks'):
            lines.append(f"\nArchitecture APKs ({len(extraction_result['arch_apks'])}):")
            for arch, path in extraction_result['arch_apks'].items():
                size_mb = os.path.getsize(path) / (1024 * 1024)
                lines.append(f"  • {arch}: {os.path.basename(path)} ({size_mb:.1f}M)")
        else:
            lines.append("\n❌ Architecture APKs: NONE FOUND")

        if extraction_result.get('config_apks'):
            lines.append(f"\nConfig APKs: {len(extraction_result['config_apks'])} (density, language, etc.)")

        # Show warnings
        if extraction_result.get('warnings'):
            lines.append("\n" + "=" * 80)
            lines.append("⚠️  WARNINGS")
            lines.append("=" * 80)
            for warning in extraction_result['warnings']:
                lines.append(warning)

        lines.append("=" * 80)
        return "\n".join(lines)
