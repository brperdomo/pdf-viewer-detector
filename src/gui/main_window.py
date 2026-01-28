"""
Main Window GUI
Main application window with input controls and results display.
"""

import customtkinter as ctk
from tkinter import filedialog, messagebox
import threading
from typing import Optional

from .comprehensive_results_panel import ComprehensiveResultsPanel
from ..utils.comprehensive_xapk_analyzer import ComprehensiveXAPKAnalyzer
from ..analyzers.apk_analyzer import APKAnalyzer
from ..analyzers.ipa_analyzer import IPAAnalyzer
from ..detectors.comprehensive_detector import ComprehensiveDetector


class MainWindow(ctk.CTk):
    """Main application window."""

    def __init__(self):
        """Initialize main window."""
        super().__init__()

        self.title("Library & SDK Analyzer")
        self.geometry("1000x800")

        # Set appearance mode
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Configure grid
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        # State
        self.is_analyzing = False

        # Create UI components
        self._create_header()
        self._create_input_section()
        self._create_progress_section()
        self._create_results_section()

        # Check credentials on startup
        self._check_credentials()

    def _create_header(self):
        """Create header section."""
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 10))

        ctk.CTkLabel(
            header_frame,
            text="Library & SDK Analyzer",
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(side="left")

    def _create_input_section(self):
        """Create input section."""
        input_frame = ctk.CTkFrame(self)
        input_frame.grid(row=1, column=0, sticky="ew", padx=20, pady=10)
        input_frame.grid_columnconfigure(0, weight=1)

        # Instructions
        instructions = ctk.CTkLabel(
            input_frame,
            text="Download APK/XAPK from APKCombo.com or APKPure.com, then select the file below:",
            font=ctk.CTkFont(size=12),
            text_color="gray",
            wraplength=900
        )
        instructions.grid(row=0, column=0, sticky="w", padx=10, pady=(10, 15))

        # File upload section
        file_frame = ctk.CTkFrame(input_frame, fg_color="transparent")
        file_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=(5, 10))
        file_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            file_frame,
            text="Select APK, XAPK, or IPA file:",
            font=ctk.CTkFont(size=13, weight="bold")
        ).grid(row=0, column=0, sticky="w", pady=(0, 8))

        self.file_path_label = ctk.CTkLabel(
            file_frame,
            text="No file selected",
            font=ctk.CTkFont(size=11),
            text_color="gray"
        )
        self.file_path_label.grid(row=1, column=0, sticky="w")

        ctk.CTkButton(
            file_frame,
            text="Browse Files",
            width=120,
            height=35,
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._browse_file
        ).grid(row=1, column=1, padx=(10, 0))

        # Button frame for Analyze and Clear buttons
        button_frame = ctk.CTkFrame(input_frame, fg_color="transparent")
        button_frame.grid(row=2, column=0, sticky="ew", padx=10, pady=(15, 10))
        button_frame.grid_columnconfigure(0, weight=1)
        button_frame.grid_columnconfigure(1, weight=1)

        # Analyze button
        self.analyze_btn = ctk.CTkButton(
            button_frame,
            text="Analyze",
            font=ctk.CTkFont(size=14, weight="bold"),
            height=40,
            command=self._start_analysis
        )
        self.analyze_btn.grid(row=0, column=0, sticky="ew", padx=(0, 5))

        # Clear/New Analysis button
        self.clear_btn = ctk.CTkButton(
            button_frame,
            text="Clear / New Analysis",
            font=ctk.CTkFont(size=14),
            height=40,
            command=self._clear_session,
            fg_color="#555555",
            hover_color="#666666"
        )
        self.clear_btn.grid(row=0, column=1, sticky="ew", padx=(5, 0))

    def _create_progress_section(self):
        """Create progress section."""
        self.progress_frame = ctk.CTkFrame(self)
        self.progress_frame.grid(row=2, column=0, sticky="ew", padx=20, pady=10)
        self.progress_frame.grid_columnconfigure(0, weight=1)

        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(self.progress_frame)
        self.progress_bar.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 5))
        self.progress_bar.set(0)

        # Status label
        self.status_label = ctk.CTkLabel(
            self.progress_frame,
            text="Ready",
            font=ctk.CTkFont(size=11)
        )
        self.status_label.grid(row=1, column=0, sticky="w", padx=10, pady=(0, 10))

        # Hide initially
        self.progress_frame.grid_remove()

    def _create_results_section(self):
        """Create results section."""
        results_label = ctk.CTkLabel(
            self,
            text="Results",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        results_label.grid(row=3, column=0, sticky="nw", padx=20, pady=(10, 5))

        self.results_panel = ComprehensiveResultsPanel(self, width=960, height=500)
        self.results_panel.grid(row=4, column=0, sticky="nsew", padx=20, pady=(0, 20))
        self.grid_rowconfigure(4, weight=1)

    def _browse_file(self):
        """Open file browser to select APK or IPA file."""
        try:
            # Force update and lift window before dialog
            self.update_idletasks()
            self.lift()
            self.focus_force()

            file_path = filedialog.askopenfilename(
                parent=self,
                title="Select APK, XAPK, or IPA file",
                filetypes=[
                    ("App files", "*.apk *.xapk *.ipa"),
                    ("Android APK", "*.apk"),
                    ("Android XAPK", "*.xapk"),
                    ("iOS IPA", "*.ipa"),
                    ("All files", "*.*")
                ]
            )

            if file_path:
                self.file_path_label.configure(text=file_path, text_color="white")
        except Exception as e:
            print(f"Error opening file dialog: {e}")
            messagebox.showerror("Error", f"Failed to open file dialog: {str(e)}")


    def _start_analysis(self):
        """Start analysis process."""
        if self.is_analyzing:
            return

        # Get file path
        file_path = self.file_path_label.cget("text")

        if not file_path or file_path == "No file selected":
            messagebox.showerror("Error", "Please select an APK, XAPK, or IPA file.")
            return

        # Clear previous results
        self.results_panel.clear_results()

        # Show progress
        self.progress_frame.grid()
        self.progress_bar.set(0)
        self.is_analyzing = True
        self.analyze_btn.configure(state="disabled", text="Analyzing...")

        # Run analysis in background thread
        thread = threading.Thread(
            target=self._run_analysis,
            args=(file_path,),
            daemon=True
        )
        thread.start()

    def _run_analysis(self, file_path: str):
        """
        Run analysis in background thread.

        Args:
            file_path: Path to APK/IPA file
        """
        try:
            platform = None
            file_to_analyze = file_path
            xapk_extraction_info = None  # Store XAPK extraction details

            # Determine platform from file
            if file_path:
                if file_path.endswith('.apk'):
                    platform = 'android'
                elif file_path.endswith('.xapk'):
                    platform = 'android'
                    # Comprehensive XAPK extraction - analyze ALL APKs
                    self._update_status("Extracting XAPK (all architecture splits)...")
                    xapk_extraction_info = ComprehensiveXAPKAnalyzer.extract_all_apks(file_path)

                    if not xapk_extraction_info['success']:
                        self._show_error(f"Failed to extract XAPK: {xapk_extraction_info.get('error', 'Unknown error')}")
                        return

                    file_to_analyze = xapk_extraction_info['base_apk']

                    # Show warnings if any
                    if xapk_extraction_info.get('warnings'):
                        for warning in xapk_extraction_info['warnings']:
                            print(f"XAPK WARNING: {warning}")

                    self._update_status("XAPK extracted, analyzing all APKs...")
                elif file_path.endswith('.ipa'):
                    platform = 'ios'
                else:
                    self._show_error("Unsupported file format.")
                    return

            # Analyze app
            self._update_progress(0.5)
            self._update_status("Analyzing app...")

            if platform == 'android':
                # For XAPK, analyze all APKs and merge results
                if xapk_extraction_info:
                    analysis_result = self._analyze_xapk_comprehensive(xapk_extraction_info)
                else:
                    analysis_result = self._analyze_android_app(file_to_analyze)
            elif platform == 'ios':
                analysis_result = self._analyze_ios_app(file_to_analyze)
            else:
                self._show_error("Unknown platform.")
                return

            if not analysis_result.success:
                self._show_error(f"Analysis failed: {analysis_result.error}")
                return

            # Add XAPK metadata if present
            if xapk_extraction_info:
                analysis_result.metadata['xapk_info'] = {
                    'analyzed_splits': xapk_extraction_info.get('all_apks', []),
                    'arch_apks': list(xapk_extraction_info.get('arch_apks', {}).keys()),
                    'warnings': xapk_extraction_info.get('warnings', []),
                    'manifest': xapk_extraction_info.get('manifest', {})
                }

            # Detect all libraries and SDKs
            self._update_progress(0.8)
            self._update_status("Detecting libraries and SDKs...")

            detector = ComprehensiveDetector()
            detected_libraries = detector.detect(analysis_result)

            # Display results
            self._update_progress(1.0)
            self._update_status("Complete!")

            self.after(500, lambda: self._display_results(
                analysis_result.metadata,
                detected_libraries
            ))

        except Exception as e:
            import traceback
            error_details = traceback.format_exc()
            print(f"Error details:\n{error_details}")
            self._show_error(f"Unexpected error: {str(e)}\n\nCheck terminal for details.")

        finally:
            self.after(0, self._analysis_complete)


    def _analyze_android_app(self, file_path: str):
        """Analyze Android APK."""
        analyzer = APKAnalyzer()
        return analyzer.analyze(file_path, self._update_status)

    def _analyze_xapk_comprehensive(self, xapk_extraction_info: dict):
        """Analyze XAPK comprehensively - all APKs and merge results."""
        analyzer = APKAnalyzer()

        # Analyze base APK
        self._update_status("Analyzing base APK...")
        base_result = analyzer.analyze(xapk_extraction_info['base_apk'], self._update_status)

        if not base_result.success:
            return base_result

        # Analyze architecture splits
        arch_results = {}
        arch_apks = xapk_extraction_info.get('arch_apks', {})

        for arch, apk_path in arch_apks.items():
            self._update_status(f"Analyzing {arch} architecture split...")
            result = analyzer.analyze(apk_path, self._update_status)

            if result.success:
                arch_results[arch] = result

        # Merge results
        self._update_status("Merging results from all APKs...")
        merged = ComprehensiveXAPKAnalyzer.merge_analysis_results(base_result, arch_results)

        # Update base_result with merged data
        base_result.packages = merged['packages']
        base_result.native_libs = merged['native_libs']
        base_result.metadata['native_libs_detailed'] = merged['native_libs_detailed']
        base_result.metadata['xapk_splits_analyzed'] = merged['analyzed_splits']

        return base_result

    def _analyze_ios_app(self, file_path: str):
        """Analyze iOS IPA."""
        analyzer = IPAAnalyzer()
        return analyzer.analyze(file_path, self._update_status)

    def _display_results(self, metadata, libraries):
        """Display analysis results."""
        self.results_panel.display_results(metadata, libraries)

    def _update_progress(self, value: float):
        """Update progress bar."""
        self.after(0, lambda: self.progress_bar.set(value))

    def _update_status(self, message: str):
        """Update status label."""
        self.after(0, lambda: self.status_label.configure(text=message))

    def _show_error(self, message: str):
        """Show error message."""
        self.after(0, lambda: messagebox.showerror("Error", message))

    def _analysis_complete(self):
        """Called when analysis is complete."""
        self.is_analyzing = False
        self.analyze_btn.configure(state="normal", text="Analyze")
        self.after(2000, lambda: self.progress_frame.grid_remove())

    def _clear_session(self):
        """Clear all results and reset UI for a new analysis."""
        # Clear file input
        self.file_path_label.configure(text="No file selected", text_color="gray")

        # Clear results panel
        self.results_panel.clear_results()

        # Hide progress
        self.progress_frame.grid_remove()
        self.progress_bar.set(0)
        self.status_label.configure(text="Ready")

        # Reset state
        self.is_analyzing = False
        self.analyze_btn.configure(state="normal", text="Analyze")

        # Show confirmation
        self.status_label.configure(text="Cleared - Ready for new analysis")
        self.after(2000, lambda: self.status_label.configure(text="Ready"))

    def _check_credentials(self):
        """Show welcome message on first run."""
        # Show info message on first run
        self.after(1000, lambda: messagebox.showinfo(
            "Welcome",
            "Welcome to Library & SDK Analyzer!\n\n"
            "This tool analyzes Android and iOS apps to detect:\n"
            "• PDF libraries (PSPDFKit, competitors)\n"
            "• Google Play Services & Firebase\n"
            "• AndroidX/Jetpack libraries\n"
            "• Analytics, crash reporting, and more\n\n"
            "To get started:\n"
            "1. Download APK/XAPK from APKCombo.com or APKPure.com\n"
            "2. Click Browse Files to select the downloaded file\n"
            "3. Click Analyze to detect PDF SDKs and other libraries"
        ))

