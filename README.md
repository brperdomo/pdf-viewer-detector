# PDF Viewer Detector

A desktop application for analyzing Android and iOS apps to identify PDF viewer libraries and SDKs, with special focus on competitive intelligence for PDF SDKs.

## Features

- **Simple Browse-Based Workflow**: Select downloaded APK/XAPK/IPA files for analysis
- **Comprehensive XAPK Support**: Automatically extracts and analyzes all architecture splits from XAPK files
- **Competitive Intelligence**:
  - **PSPDFKit Detection**: Shows simplified view (version only) - features verified internally via licensing
  - **Competitor Detection**: Full feature breakdown showing Premium ⭐ vs Standard 📘 features
- **Extensive Library Database**: Detects 24+ PDF libraries including:
  - **Android**: PSPDFKit, Apryse (PDFTron), Foxit, Xodo, Kdan, MuPDF, AndroidPdfViewer, and more
  - **iOS**: PSPDFKit, Apryse, PDFKit, Adobe PDF Library, Foxit, MuPDF, and more
- **Document Viewing Solutions**: Also detects non-commercial solutions (Cordova plugins, system APIs, web-based viewers)
- **SDK Version Detection**: Identifies if competitors are using recent or outdated SDK versions
- **SDK Feature Detection**: For competitors, shows which features they're using (annotations, digital signatures, collaboration, etc.)
- **Detailed Results**: View confidence scores, detection methods, and matched signatures
- **Export Options**: Export results as JSON or CSV, or copy to clipboard
- **Modern GUI**: Clean, dark-themed interface built with CustomTkinter

## Installation

### Prerequisites

- Python 3.11 or higher
- No external tools required!

### Step 1: Clone the Repository

```bash
git clone https://github.com/yourusername/pdf-viewer-detector.git
cd pdf-viewer-detector
```

### Step 2: Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On macOS/Linux
# or
venv\Scripts\activate  # On Windows
```

### Step 3: Install Python Dependencies

```bash
pip install -r requirements.txt
```

## Usage

### Running the Application

```bash
python -m src.gui.main_window
```

### Analyzing Apps

**Simple 3-Step Process:**

1. **Download APK/XAPK** manually from:
   - APKCombo: https://apkcombo.com/
   - APKPure: https://apkpure.com/
   - APKMirror: https://www.apkmirror.com/

2. **Click "Browse Files"** in the app and select the downloaded file

3. **Click "Analyze"** to detect PDF SDKs and other libraries

**Note:** XAPK files (used by APKPure) are automatically extracted and all architecture splits are analyzed

### Viewing Results

After analysis completes, you'll see:

- **App Information**: Name, version, package, size, SDK versions, etc.
- **XAPK Analysis Breakdown** (if applicable): Shows which APKs were analyzed and any warnings
- **PDF Libraries Detected**:
  - **PSPDFKit**: Simple view showing version only (feature details available internally)
  - **Competitors**: Full feature breakdown with Premium ⭐ and Standard 📘 indicators
- **Other Document Viewing Solutions**: Non-commercial plugins and system APIs
- **Native Libraries**: All .so files with architecture details
- **Java Packages**: Top-level packages detected
- **Other SDKs**: Firebase, AndroidX, Analytics, Crash Reporting, etc.

### Exporting Results

- **Export as JSON**: Complete data structure for programmatic use
- **Export as CSV**: Spreadsheet-friendly format
- **Copy to Clipboard**: Quick text summary

## Architecture

### Project Structure

```
pdf-viewer-detector/
├── src/
│   ├── gui/
│   │   ├── main_window.py                    # Main GUI window
│   │   └── comprehensive_results_panel.py    # Results display component
│   ├── analyzers/
│   │   ├── apk_analyzer.py                   # APK analysis (androguard)
│   │   └── ipa_analyzer.py                   # IPA framework analyzer
│   ├── detectors/
│   │   └── comprehensive_detector.py         # PDF library + SDK detection
│   └── utils/
│       ├── comprehensive_xapk_analyzer.py    # XAPK extraction and analysis
│       └── apk_downloader.py                 # APKCombo/APKPure downloader (fallback)
├── data/
│   ├── pdf_libraries.json                    # PDF library signatures (24+ libraries)
│   ├── pdf_sdk_features.json                 # Feature signatures for SDKs
│   ├── pdf_sdk_version_patterns.json         # Version detection patterns
│   └── document_viewing_solutions.json       # Non-commercial solutions
├── requirements.txt
└── README.md
```

### How It Works

1. **File Selection**: User browses and selects APK, XAPK, or IPA file
2. **XAPK Extraction**: If XAPK, extracts base + all architecture-specific APKs
3. **Analysis**:
   - **Android**: Uses `androguard` to parse APK, extract packages, classes, and native libraries
   - **iOS**: Extracts IPA (ZIP), parses Info.plist, and scans Frameworks directory
4. **Comprehensive Detection**:
   - Matches against 24+ PDF library signatures
   - Detects SDK versions using pattern matching
   - Identifies features for competitive intelligence
   - Detects non-commercial document viewing solutions
5. **Display**: Shows results with differential treatment (PSPDFKit vs competitors)

## Detected Libraries

### Android PDF Libraries

**Commercial SDKs:**
- PSPDFKit
- Apryse (formerly PDFTron)
- Foxit PDF SDK
- Xodo PDF SDK
- Kdan PDF SDK
- Radaee PDF SDK
- Syncfusion PDF
- ComponentOne PDF
- DevExpress PDF

**Open Source & Free:**
- AndroidPdfViewer (barteksc)
- Android PdfRenderer (System API)
- MuPDF
- Apache PDFBox
- iText
- OpenPDF
- PDF.js (WebView-based)

**Non-Commercial Document Viewing:**
- Cordova Document Viewer Plugin
- Android System Intent
- Google Drive Viewer
- Microsoft Office Viewer
- WebView PDF viewers

### iOS PDF Libraries

- PSPDFKit
- Apryse (PDFTron)
- PDFKit (Apple native)
- Adobe PDF Library (RPSDK)
- Foxit PDF SDK
- MuPDF
- CGPDFDocument
- PDF.js

## Competitive Intelligence Features

### For PSPDFKit
- Shows detection with confidence
- Shows SDK version if detected
- **Does not show feature breakdown** (features verified internally via licensing)
- Note: "Feature details available via internal licensing database"

### For Competitors (Apryse, Foxit, Xodo, etc.)
- Shows detection with confidence
- Shows SDK version with status (Recent/Moderate/Outdated)
- **Shows full feature breakdown**:
  - **Premium Features** ⭐: Digital Signatures, Instant Collaboration, Redaction, Document Comparison, OCR, Measurement Tools
  - **Standard Features** 📘: Annotations, Forms, Document Editing, UI Components
- Shows evidence for each detected feature
- Helps understand competitor capabilities

## Limitations

1. **Manual Download Required**: APK/XAPK files must be downloaded manually from APKCombo, APKPure, or APKMirror. Automated downloading is not supported due to anti-bot protection on these sites.

2. **Detection Accuracy**:
   - **Package/class detection**: ~90-95% accurate
   - **Feature detection**: ~70-80% accurate (presence of code doesn't guarantee licensing/usage)
   - False positives possible if app uses similar package names
   - False negatives possible if:
     - Libraries are heavily obfuscated (ProGuard/R8)
     - PDF functionality is implemented through web views
     - Runtime downloads are used

3. **XAPK Completeness**: Some XAPK downloads may be incomplete (missing ARM APKs). Tool warns you when this happens.

4. **Feature Detection Limitations**:
   - Can detect code presence but not actual licensing tier
   - Can't determine if features are enabled/used
   - Obfuscation can hide features

## Troubleshooting

### "No PDF libraries detected" but you know the app uses one

- **XAPK may be incomplete**: Check the XAPK Analysis Breakdown section for warnings. If only x86/x86_64 APKs were found, native libraries (including PDF SDKs) won't be present.
- **Try a different download source**: APKCombo, APKPure, or APKMirror may have more complete packages
- **Obfuscation**: The app may use heavy ProGuard/R8 obfuscation

### Analysis takes too long

- Large apps (>100MB) may take several minutes to analyze
- XAPK analysis takes longer as it analyzes multiple APKs

### "Failed to extract XAPK"

- File may be corrupted - try downloading again
- File may not be a valid XAPK format

## Development

### Adding New PDF Libraries

To add detection for a new PDF library:

1. Open `data/pdf_libraries.json`

2. Add a new entry under `android_libraries` or `ios_libraries`:

```json
{
  "name": "LibraryName",
  "description": "Description of the library",
  "signatures": {
    "packages": ["com.example.package"],
    "classes": ["LibraryClassName"],
    "native_libs": ["libLibraryName.so"],
    "files": ["LibraryName.framework"]
  },
  "confidence_weight": 95
}
```

3. Restart the application

### Adding SDK Features

To add feature detection for an SDK:

1. Open `data/pdf_sdk_features.json`

2. Add features under the SDK name:

```json
{
  "sdk_name": {
    "features": {
      "feature_key": {
        "name": "Feature Name",
        "description": "What this feature does",
        "signatures": {
          "packages": ["com.sdk.feature"],
          "classes": ["FeatureClass"]
        },
        "tier": "premium"  // or "standard"
      }
    }
  }
}
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

This project is licensed under the MIT License.

## Disclaimer

This tool is for competitive intelligence and research purposes only. Always respect app developers' intellectual property rights and terms of service.

## Credits

Built with:
- [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) - Modern GUI framework
- [Androguard](https://github.com/androguard/androguard) - Android app analysis
- [BeautifulSoup4](https://www.crummy.com/software/BeautifulSoup/) - HTML parsing

## Changelog

### Version 2.0.0 (2026-01-27)
- Simplified to browse-only workflow (removed URL downloads)
- Added competitive intelligence features
- Differential feature detection (PSPDFKit vs competitors)
- Comprehensive XAPK analysis (all architecture splits)
- SDK version detection
- SDK feature detection with Premium/Standard tiers
- Added 24+ PDF library signatures
- Added document viewing solutions detection
- Removed Apple Configurator integration
- Removed Settings/credentials management
- Clear/New Analysis button for multiple analyses

### Version 1.0.0 (2026-01-26)
- Initial release
