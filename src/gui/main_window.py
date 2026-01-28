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
from ..utils.analysis_cache import AnalysisCache
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
        self.current_package_name = None

        # Initialize cache
        self.cache = AnalysisCache()

        # Create UI components
        self._create_header()
        self._create_input_section()
        self._create_progress_section()
        self._create_results_section()

        # Show welcome message on startup
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

        # History button
        stats = self.cache.get_stats()
        history_text = f"History ({stats['total_analyses']})"

        self.history_btn = ctk.CTkButton(
            header_frame,
            text=history_text,
            width=120,
            command=self._show_history
        )
        self.history_btn.pack(side="right", padx=5)

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

    def _get_quick_package_info(self, file_path: str) -> Optional[dict]:
        """
        Quickly extract package info for cache lookup without full analysis.

        Args:
            file_path: Path to APK/XAPK/IPA file

        Returns:
            Dictionary with package_name, version_name, version_code or None
        """
        try:
            if file_path.endswith('.apk'):
                from androguard.core.apk import APK
                apk = APK(file_path)
                return {
                    'package_name': apk.get_package(),
                    'version_name': str(apk.get_androidversion_name()) if apk.get_androidversion_name() else 'Unknown',
                    'version_code': str(apk.get_androidversion_code()) if apk.get_androidversion_code() else ''
                }
            elif file_path.endswith('.xapk'):
                # For XAPK, extract and check the base APK
                import zipfile
                import json
                with zipfile.ZipFile(file_path, 'r') as xapk_zip:
                    # Try to read manifest.json first
                    if 'manifest.json' in xapk_zip.namelist():
                        manifest_data = json.loads(xapk_zip.read('manifest.json'))
                        return {
                            'package_name': manifest_data.get('package_name', 'unknown'),
                            'version_name': manifest_data.get('version_name', 'Unknown'),
                            'version_code': str(manifest_data.get('version_code', ''))
                        }
            elif file_path.endswith('.ipa'):
                import zipfile
                import plistlib
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    # Find .app directory
                    app_dirs = [name for name in zip_ref.namelist()
                               if '.app/' in name and not name.startswith('__MACOSX')]
                    if app_dirs:
                        app_dir = app_dirs[0].split('.app/')[0] + '.app/'
                        plist_path = f"{app_dir}Info.plist"
                        if plist_path in zip_ref.namelist():
                            plist_data = plistlib.loads(zip_ref.read(plist_path))
                            return {
                                'package_name': plist_data.get('CFBundleIdentifier', 'unknown'),
                                'version_name': plist_data.get('CFBundleShortVersionString', 'Unknown'),
                                'version_code': str(plist_data.get('CFBundleVersion', ''))
                            }
        except Exception as e:
            print(f"Error extracting quick package info: {e}")

        return None

    def _start_analysis(self):
        """Start analysis process."""
        if self.is_analyzing:
            return

        # Get file path
        file_path = self.file_path_label.cget("text")

        if not file_path or file_path == "No file selected":
            messagebox.showerror("Error", "Please select an APK, XAPK, or IPA file.")
            return

        # Check cache first
        package_info = self._get_quick_package_info(file_path)
        if package_info:
            cached_analysis = self.cache.get_analysis(
                package_name=package_info['package_name'],
                version_name=package_info.get('version_name'),
                version_code=package_info.get('version_code')
            )

            if cached_analysis:
                # Found cached results - ask user what to do
                from datetime import datetime
                analyzed_date = datetime.fromisoformat(cached_analysis['analyzed_date'])
                date_str = analyzed_date.strftime("%Y-%m-%d at %H:%M")

                result = messagebox.askyesnocancel(
                    "Cached Analysis Found",
                    f"This app was previously analyzed on {date_str}.\n\n"
                    f"App: {cached_analysis['app_name']}\n"
                    f"Version: {cached_analysis['version_name']}\n\n"
                    f"• Click 'Yes' to load cached results (instant)\n"
                    f"• Click 'No' to re-analyze (may take a few minutes)\n"
                    f"• Click 'Cancel' to abort",
                    icon='question'
                )

                if result is None:  # Cancel
                    return
                elif result:  # Yes - load cached
                    self._load_cached_analysis(cached_analysis)
                    return
                # If No - continue with fresh analysis below

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

            # Save to cache
            self._update_status("Saving to cache...")
            package_name = analysis_result.metadata.get('package_name', 'unknown')
            self.current_package_name = package_name
            self.cache.save_analysis(
                package_name=package_name,
                app_metadata=analysis_result.metadata,
                detected_libraries=detected_libraries,
                platform=platform,
                file_path=file_path
            )

            # Update history count in header
            self._update_history_count()

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

    def _update_history_count(self):
        """Update the History button text with current count."""
        def update():
            stats = self.cache.get_stats()
            history_text = f"History ({stats['total_analyses']})"
            self.history_btn.configure(text=history_text)
        self.after(0, update)

    def _show_history(self):
        """Show analysis history dialog."""
        dialog = HistoryDialog(self, self.cache, self._load_cached_analysis)
        # Wait for dialog to close, then update count in case items were deleted
        dialog.wait_window()
        self._update_history_count()

    def _load_cached_analysis(self, cached_data: dict):
        """
        Load a cached analysis into the results panel.

        Args:
            cached_data: Cached analysis data
        """
        self.results_panel.clear_results()
        self.results_panel.display_results(
            cached_data['app_metadata'],
            cached_data['detected_libraries']
        )

        # Update status
        from datetime import datetime
        analyzed_date = datetime.fromisoformat(cached_data['analyzed_date'])
        date_str = analyzed_date.strftime("%Y-%m-%d %H:%M")
        self.status_label.configure(text=f"Loaded cached analysis from {date_str}")

        # Update file path label if available
        if cached_data.get('file_path'):
            self.file_path_label.configure(
                text=f"{cached_data['file_path']} (cached)",
                text_color="#4CAF50"
            )

    def _check_credentials(self):
        """Show welcome message on first run."""
        # Show info message on first run
        stats = self.cache.get_stats()
        if stats['total_analyses'] == 0:
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



class HistoryDialog(ctk.CTkToplevel):
    """Dialog for browsing analysis history."""

    def __init__(self, parent, cache: 'AnalysisCache', load_callback):
        """
        Initialize history dialog.

        Args:
            parent: Parent window
            cache: AnalysisCache instance
            load_callback: Callback function when analysis is selected
        """
        super().__init__(parent)

        self.cache = cache
        self.load_callback = load_callback

        self.title("Analysis History")
        self.geometry("900x600")

        # Configure grid
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Header
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 10))

        stats = self.cache.get_stats()
        title_text = f"Analysis History - {stats['total_analyses']} Total"

        ctk.CTkLabel(
            header_frame,
            text=title_text,
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(side="left")

        # Clear all button
        ctk.CTkButton(
            header_frame,
            text="Clear All",
            width=100,
            fg_color="#E74C3C",
            hover_color="#C0392B",
            command=self._clear_all
        ).pack(side="right", padx=(10, 0))

        # Refresh button
        ctk.CTkButton(
            header_frame,
            text="Refresh",
            width=100,
            command=self._refresh_list
        ).pack(side="right")

        # Scrollable frame for history list
        self.scrollable_frame = ctk.CTkScrollableFrame(self, width=860, height=450)
        self.scrollable_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=10)
        self.scrollable_frame.grid_columnconfigure(0, weight=1)

        # Configure smoother scrolling
        self.after(100, self._configure_smooth_scrolling)

        # Populate list
        self._populate_list()

        # Close button
        ctk.CTkButton(
            self,
            text="Close",
            width=100,
            command=self.destroy
        ).grid(row=2, column=0, padx=20, pady=(0, 20))

        self.grab_set()

    def _configure_smooth_scrolling(self):
        """Configure smoother scrolling behavior for history list."""
        try:
            # Access the internal canvas from CTkScrollableFrame
            if hasattr(self.scrollable_frame, '_parent_canvas'):
                canvas = self.scrollable_frame._parent_canvas
                # Configure scrolling parameters for smoother behavior
                canvas.configure(yscrollincrement=20)
        except:
            pass

    def _populate_list(self):
        """Populate the list of cached analyses."""
        # Clear existing widgets
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()

        analyses = self.cache.get_all_analyses()

        if not analyses:
            ctk.CTkLabel(
                self.scrollable_frame,
                text="No cached analyses found.",
                font=ctk.CTkFont(size=12),
                text_color="gray"
            ).pack(pady=40)
            return

        # Create card for each analysis
        for idx, analysis in enumerate(analyses):
            self._create_history_card(analysis, idx)

    def _create_history_card(self, analysis: dict, index: int):
        """
        Create a card widget for a cached analysis.

        Args:
            analysis: Analysis summary dictionary
            index: Index in the list
        """
        # Card frame
        card = ctk.CTkFrame(self.scrollable_frame, fg_color="#2B2B2B", corner_radius=10)
        card.pack(fill="x", padx=5, pady=8)
        card.grid_columnconfigure(0, weight=1)

        # Header row with app name and platform
        header_row = ctk.CTkFrame(card, fg_color="transparent")
        header_row.grid(row=0, column=0, sticky="ew", padx=15, pady=(12, 5))
        header_row.grid_columnconfigure(0, weight=1)

        # App name
        app_name = analysis.get('app_name', 'Unknown App')
        name_label = ctk.CTkLabel(
            header_row,
            text=app_name,
            font=ctk.CTkFont(size=15, weight="bold"),
            anchor="w"
        )
        name_label.grid(row=0, column=0, sticky="w")

        # Platform badge
        platform = analysis.get('platform', 'unknown')
        platform_color = "#3DDC84" if platform == "android" else "#147EFB"
        platform_label = ctk.CTkLabel(
            header_row,
            text=platform.upper(),
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color="white",
            fg_color=platform_color,
            corner_radius=4,
            padx=8,
            pady=2
        )
        platform_label.grid(row=0, column=1, sticky="e", padx=(10, 0))

        # Details row
        details_text = f"{analysis['package_name']}"
        if analysis.get('version_name'):
            details_text += f" • v{analysis['version_name']}"

        details_label = ctk.CTkLabel(
            card,
            text=details_text,
            font=ctk.CTkFont(size=11),
            text_color="gray",
            anchor="w"
        )
        details_label.grid(row=1, column=0, sticky="w", padx=15, pady=(0, 5))

        # Date row
        from datetime import datetime
        analyzed_date = datetime.fromisoformat(analysis['analyzed_date'])
        date_str = analyzed_date.strftime("%Y-%m-%d %H:%M")

        date_label = ctk.CTkLabel(
            card,
            text=f"📅 Analyzed: {date_str}",
            font=ctk.CTkFont(size=10),
            text_color="#888888",
            anchor="w"
        )
        date_label.grid(row=2, column=0, sticky="w", padx=15, pady=(0, 5))

        # Button row
        button_row = ctk.CTkFrame(card, fg_color="transparent")
        button_row.grid(row=3, column=0, sticky="ew", padx=15, pady=(5, 12))

        # Load button
        load_btn = ctk.CTkButton(
            button_row,
            text="Load Results",
            width=120,
            height=32,
            fg_color="#4CAF50",
            hover_color="#45A049",
            command=lambda: self._load_analysis(analysis['id'])
        )
        load_btn.pack(side="left", padx=(0, 10))

        # Delete button
        delete_btn = ctk.CTkButton(
            button_row,
            text="Delete",
            width=80,
            height=32,
            fg_color="#666666",
            hover_color="#555555",
            command=lambda: self._delete_analysis(analysis['id'])
        )
        delete_btn.pack(side="left")

    def _load_analysis(self, analysis_id: int):
        """Load a cached analysis."""
        # Get full cached data
        analyses = self.cache.get_all_analyses()
        selected = None
        for analysis in analyses:
            if analysis['id'] == analysis_id:
                # Get full data
                package_name = analysis['package_name']
                version_name = analysis.get('version_name')
                version_code = analysis.get('version_code')
                cached_data = self.cache.get_analysis(package_name, version_name, version_code)
                if cached_data:
                    self.load_callback(cached_data)
                    self.destroy()
                break

    def _delete_analysis(self, analysis_id: int):
        """Delete a cached analysis."""
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this analysis?"):
            if self.cache.delete_analysis(analysis_id):
                self._refresh_list()
                messagebox.showinfo("Success", "Analysis deleted successfully!")
            else:
                messagebox.showerror("Error", "Failed to delete analysis.")

    def _clear_all(self):
        """Clear all cached analyses."""
        if messagebox.askyesno(
            "Confirm Clear All",
            "Are you sure you want to delete ALL cached analyses?\nThis cannot be undone."
        ):
            if self.cache.clear_all():
                self._refresh_list()
                messagebox.showinfo("Success", "All analyses cleared!")
            else:
                messagebox.showerror("Error", "Failed to clear analyses.")

    def _refresh_list(self):
        """Refresh the history list."""
        self._populate_list()

        # Update header
        stats = self.cache.get_stats()
        self.title(f"Analysis History - {stats['total_analyses']} Total")


if __name__ == "__main__":
    app = MainWindow()
    app.mainloop()
