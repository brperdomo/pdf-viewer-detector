"""
Debug APK Analysis Tool
Helps diagnose why libraries aren't being detected.
"""

import sys
from src.analyzers.apk_analyzer import APKAnalyzer
from src.detectors.comprehensive_detector import ComprehensiveDetector

def debug_apk(apk_path: str):
    """Debug an APK to see what's being extracted."""

    print("=" * 80)
    print("DEBUG APK ANALYSIS")
    print("=" * 80)
    print(f"File: {apk_path}")
    print()

    # Analyze APK
    print("Analyzing APK...")
    analyzer = APKAnalyzer()
    result = analyzer.analyze(apk_path)

    if not result.success:
        print(f"ERROR: {result.error}")
        return

    print("✓ Analysis successful")
    print()

    # Show metadata
    print("=" * 80)
    print("METADATA")
    print("=" * 80)
    for key, value in result.metadata.items():
        if key not in ['permissions', 'package_class_counts', 'native_libs_detailed']:
            print(f"{key}: {value}")
    print()

    # Show packages (filtered for PDF-related)
    print("=" * 80)
    print("PDF-RELATED PACKAGES (contains: pdf, pspdf, adobe, foxit, mupdf, radaee)")
    print("=" * 80)
    pdf_keywords = ['pdf', 'pspdf', 'adobe', 'foxit', 'mupdf', 'radaee', 'itext', 'pdfbox']
    pdf_packages = [p for p in result.packages if any(kw in p.lower() for kw in pdf_keywords)]

    if pdf_packages:
        for pkg in sorted(pdf_packages):
            print(f"  • {pkg}")
    else:
        print("  No PDF-related packages found")
    print(f"\nTotal packages: {len(result.packages)}")
    print()

    # Show native libraries
    print("=" * 80)
    print("NATIVE LIBRARIES")
    print("=" * 80)
    native_libs_detailed = result.metadata.get('native_libs_detailed', [])
    if native_libs_detailed:
        # Group by name
        lib_names = {}
        for lib in native_libs_detailed:
            name = lib['name']
            if name not in lib_names:
                lib_names[name] = []
            lib_names[name].append(lib['architecture'])

        for name, archs in sorted(lib_names.items()):
            print(f"  • {name} [{', '.join(archs)}]")
    else:
        print("  No native libraries found")
    print(f"\nTotal native library files: {len(native_libs_detailed)}")
    print()

    # Show files
    print("=" * 80)
    print("PDF-RELATED FILES (JAR/resources)")
    print("=" * 80)
    pdf_files = [f for f in result.files if any(kw in f.lower() for kw in pdf_keywords)]
    if pdf_files:
        for file in sorted(pdf_files):
            print(f"  • {file}")
    else:
        print("  No PDF-related files found")
    print()

    # Show classes
    print("=" * 80)
    print("PDF-RELATED CLASSES")
    print("=" * 80)
    if result.classes:
        for cls in sorted(result.classes)[:50]:  # Limit to first 50
            print(f"  • {cls}")
        if len(result.classes) > 50:
            print(f"  ... and {len(result.classes) - 50} more")
    else:
        print("  No PDF-related classes found")
    print()

    # Run detection
    print("=" * 80)
    print("DETECTION RESULTS")
    print("=" * 80)
    detector = ComprehensiveDetector()
    detected_libs = detector.detect(result)

    pdf_libs = detected_libs.get('pdf_libraries', [])
    if pdf_libs:
        print(f"Found {len(pdf_libs)} PDF libraries:")
        for lib in pdf_libs:
            print(f"\n  • {lib['name']}")
            print(f"    Confidence: {lib['confidence']}%")
            print(f"    Matched: {', '.join(lib['matched_signatures'])}")
    else:
        print("❌ NO PDF LIBRARIES DETECTED")
        print()
        print("Checking why PSPDFKit wasn't detected:")
        print("PSPDFKit signatures:")
        print("  Packages: com.pspdfkit, com.pspdfkit.ui, com.pspdfkit.annotations, etc.")
        print("  Classes: PSPDFKit, PdfActivity, PdfFragment")
        print("  Files: pspdfkit, PSPDFKit")
        print("  Native libs: libpspdfkit.so, libPSPDFKit.so")
        print()
        print("Check if any of these appear in the data above.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python debug_apk.py <path_to_apk>")
        sys.exit(1)

    debug_apk(sys.argv[1])
