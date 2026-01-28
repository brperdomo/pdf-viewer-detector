#!/usr/bin/env python3
"""
Comprehensive XAPK Audit Tool
Analyzes ALL APKs in an XAPK (base + architecture splits) to find PDF libraries.
Shows exactly what was analyzed for full transparency.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from src.utils.comprehensive_xapk_analyzer import ComprehensiveXAPKAnalyzer
from src.analyzers.apk_analyzer import APKAnalyzer
from src.detectors.comprehensive_detector import ComprehensiveDetector


def comprehensive_xapk_audit(xapk_path: str):
    """Perform comprehensive audit of XAPK file."""

    print("=" * 80)
    print("COMPREHENSIVE XAPK AUDIT")
    print("=" * 80)
    print(f"File: {xapk_path}")
    print()

    # Step 1: Extract all APKs
    print("STEP 1: Extracting XAPK...")
    print("-" * 80)
    extraction = ComprehensiveXAPKAnalyzer.extract_all_apks(xapk_path)

    if not extraction['success']:
        print(f"❌ ERROR: {extraction.get('error', 'Unknown error')}")
        return

    # Show what we found
    print(ComprehensiveXAPKAnalyzer.create_analysis_summary(extraction))
    print()

    # Step 2: Analyze base APK
    print("=" * 80)
    print("STEP 2: Analyzing Base APK...")
    print("=" * 80)

    analyzer = APKAnalyzer()
    base_result = analyzer.analyze(extraction['base_apk'])

    if not base_result.success:
        print(f"❌ Base APK analysis failed: {base_result.error}")
        return

    print(f"✅ Base APK analyzed successfully")
    print(f"   Packages: {len(base_result.packages)}")
    print(f"   Classes: {len(base_result.classes)}")
    print(f"   Permissions: {len(base_result.metadata.get('permissions', []))}")
    print()

    # Step 3: Analyze architecture splits
    print("=" * 80)
    print("STEP 3: Analyzing Architecture Splits...")
    print("=" * 80)

    arch_results = {}
    for arch, apk_path in extraction['arch_apks'].items():
        print(f"\nAnalyzing {arch}...")
        result = analyzer.analyze(apk_path)
        if result.success:
            arch_results[arch] = result
            native_libs = result.metadata.get('native_libs_detailed', [])
            print(f"   ✅ Found {len(native_libs)} native libraries")

            # Show native libraries
            if native_libs:
                lib_names = set(lib['name'] for lib in native_libs)
                for lib_name in sorted(lib_names)[:10]:  # Show first 10
                    print(f"      • {lib_name}")
                if len(lib_names) > 10:
                    print(f"      ... and {len(lib_names) - 10} more")
        else:
            print(f"   ⚠️  Analysis failed: {result.error}")

    # Step 4: Merge results
    print("\n" + "=" * 80)
    print("STEP 4: Merging Results from All APKs...")
    print("=" * 80)

    merged = ComprehensiveXAPKAnalyzer.merge_analysis_results(base_result, arch_results)

    print(f"Combined Analysis:")
    print(f"   Total Packages: {len(merged['packages'])}")
    print(f"   Total Classes: {len(merged['classes'])}")
    print(f"   Total Native Libraries: {len(merged['native_libs'])}")
    print(f"   Splits Analyzed: {', '.join(merged['analyzed_splits'])}")
    print()

    # Show all native libraries found
    if merged['native_libs']:
        print("All Native Libraries Found:")
        print("-" * 80)
        # Group by name
        lib_details = merged['native_libs_detailed']
        lib_groups = {}
        for lib in lib_details:
            name = lib['name']
            if name not in lib_groups:
                lib_groups[name] = []
            lib_groups[name].append(lib['architecture'])

        for name, archs in sorted(lib_groups.items()):
            print(f"  • {name} [{', '.join(archs)}]")
    else:
        print("⚠️  NO NATIVE LIBRARIES FOUND IN ANY APK")

    print()

    # Step 5: Detect PDF libraries
    print("=" * 80)
    print("STEP 5: PDF Library Detection")
    print("=" * 80)

    # Update base_result with merged data
    base_result.packages = merged['packages']
    base_result.native_libs = merged['native_libs']
    base_result.metadata['native_libs_detailed'] = merged['native_libs_detailed']

    detector = ComprehensiveDetector()
    detected = detector.detect(base_result)

    pdf_libs = detected.get('pdf_libraries', [])

    if pdf_libs:
        print(f"✅ Found {len(pdf_libs)} PDF libraries:")
        print()
        for lib in pdf_libs:
            print(f"  • {lib['name']}")
            print(f"    Description: {lib['description']}")
            print(f"    Confidence: {lib['confidence']}%")
            print(f"    Matched Signatures:")
            for sig in lib['matched_signatures']:
                print(f"       - {sig}")
            print()
    else:
        print("❌ NO PDF LIBRARIES DETECTED")
        print()
        print("Checked against 24 PDF libraries:")
        print("   ✅ PSPDFKit")
        print("   🔴 Apryse/PDFTron (major competitor)")
        print("   🔴 Foxit, Xodo, Kdan (competitors)")
        print("   📘 MuPDF, iText, PDFBox, and 17 others")
        print()
        print("If you're confident this app uses a PDF SDK:")
        print("   1. Check if ARM architecture APKs are missing (see warnings above)")
        print("   2. Get the app from Google Play Store instead")
        print("   3. The SDK might be added in a newer version")

    # Cleanup
    import shutil
    try:
        shutil.rmtree(extraction['output_dir'])
    except:
        pass


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python comprehensive_xapk_audit.py <path_to_xapk>")
        sys.exit(1)

    comprehensive_xapk_audit(sys.argv[1])
