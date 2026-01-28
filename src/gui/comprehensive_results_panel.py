"""
Comprehensive Results Panel
Displays comprehensive library analysis results with PDF highlighting.
"""

import customtkinter as ctk
from typing import Dict, Optional
import json
import csv
from pathlib import Path
from tkinter import messagebox


class ComprehensiveResultsPanel(ctk.CTkScrollableFrame):
    """Panel to display comprehensive library analysis results."""

    def __init__(self, parent, **kwargs):
        """Initialize results panel."""
        super().__init__(parent, **kwargs)

        self.app_metadata = {}
        self.detected_libraries = {}

        # Configure grid
        self.grid_columnconfigure(0, weight=1)

        # Export buttons frame
        self.export_frame = None

        # Fix scrolling behavior after initialization
        self.after(100, self._configure_smooth_scrolling)

    def _configure_smooth_scrolling(self):
        """Configure smoother scrolling behavior."""
        try:
            # Access the internal canvas from CTkScrollableFrame
            if hasattr(self, '_parent_canvas'):
                canvas = self._parent_canvas
                # Configure scrolling parameters for smoother behavior
                canvas.configure(yscrollincrement=20)
        except:
            pass

    def display_results(self, app_metadata: Dict, detected_libraries: Dict):
        """
        Display comprehensive analysis results.

        Args:
            app_metadata: App metadata dictionary
            detected_libraries: Dictionary of categorized detected libraries
        """
        # Clear previous results
        self.clear_results()

        self.app_metadata = app_metadata
        self.detected_libraries = detected_libraries

        row = 0

        # Export buttons at top
        self._create_export_buttons(row)
        row += 1

        # XAPK Analysis Info (if present)
        if 'xapk_info' in app_metadata:
            self._display_xapk_info(row, app_metadata['xapk_info'])
            row += 1

        # App Information
        self._display_app_info(row)
        row += 1

        # PDF Libraries (HIGHLIGHTED)
        pdf_libs = detected_libraries.get('pdf_libraries', [])
        if pdf_libs:
            self._display_pdf_libraries(row, pdf_libs)
            row += 1

        # Document Viewing Solutions (non-commercial)
        doc_solutions = detected_libraries.get('document_viewing_solutions', [])
        if doc_solutions:
            self._display_document_viewing_solutions(row, doc_solutions)
            row += 1

        # Native Libraries (always show, even if empty)
        native_libs = app_metadata.get('native_libs_detailed', [])
        self._display_native_libraries(row, native_libs)
        row += 1

        # Java Packages Summary (always show)
        package_counts = app_metadata.get('package_class_counts', {})
        self._display_package_summary(row, package_counts)
        row += 1

        # Google Play Services & Firebase
        gps_libs = detected_libraries.get('google_play_services', [])
        firebase_libs = detected_libraries.get('firebase', [])
        if gps_libs or firebase_libs:
            self._display_google_firebase(row, gps_libs, firebase_libs)
            row += 1

        # AndroidX Libraries
        androidx_libs = detected_libraries.get('androidx', [])
        if androidx_libs:
            self._display_androidx(row, androidx_libs)
            row += 1

        # Kotlin Libraries
        kotlin_libs = detected_libraries.get('kotlin', [])
        if kotlin_libs:
            self._display_kotlin(row, kotlin_libs)
            row += 1

        # Analytics SDKs
        analytics_libs = detected_libraries.get('analytics', [])
        if analytics_libs:
            self._display_category_section(row, "Analytics SDKs", analytics_libs, "#FF9800")
            row += 1

        # Crash Reporting
        crash_libs = detected_libraries.get('crash_reporting', [])
        if crash_libs:
            self._display_category_section(row, "Crash Reporting & Monitoring", crash_libs, "#E91E63")
            row += 1

        # Networking
        network_libs = detected_libraries.get('networking', [])
        if network_libs:
            self._display_category_section(row, "Networking & HTTP", network_libs, "#2196F3")
            row += 1

        # UI Libraries
        ui_libs = detected_libraries.get('ui_libraries', [])
        if ui_libs:
            self._display_category_section(row, "UI Libraries", ui_libs, "#9C27B0")
            row += 1

        # Dependency Injection
        di_libs = detected_libraries.get('dependency_injection', [])
        if di_libs:
            self._display_category_section(row, "Dependency Injection", di_libs, "#795548")
            row += 1

        # Social SDKs
        social_libs = detected_libraries.get('social', [])
        if social_libs:
            self._display_category_section(row, "Social SDKs", social_libs, "#3F51B5")
            row += 1

        # Permissions
        permissions = app_metadata.get('permissions', [])
        if permissions:
            self._display_permissions(row, permissions)
            row += 1

        # Hardware Features
        features = app_metadata.get('hardware_features', [])
        if features:
            self._display_hardware_features(row, features)
            row += 1

        # Assets & Resources Summary
        assets = app_metadata.get('assets', {})
        resources = app_metadata.get('resources', {})
        if assets or resources:
            self._display_assets_resources(row, assets, resources)
            row += 1

    def _create_export_buttons(self, row):
        """Create export buttons."""
        self.export_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.export_frame.grid(row=row, column=0, sticky="ew", padx=10, pady=10)

        ctk.CTkButton(
            self.export_frame,
            text="Export JSON",
            width=120,
            command=self._export_json
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            self.export_frame,
            text="Export CSV",
            width=120,
            command=self._export_csv
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            self.export_frame,
            text="Copy to Clipboard",
            width=140,
            command=self._copy_to_clipboard
        ).pack(side="left", padx=5)

    def _display_xapk_info(self, row, xapk_info):
        """Display XAPK analysis breakdown and warnings."""
        # Determine color based on warnings
        has_warnings = bool(xapk_info.get('warnings'))
        color = "#FF9800" if has_warnings else "#4CAF50"  # Orange if warnings, green otherwise

        frame = self._create_section_frame(row, "📦 XAPK Analysis Breakdown", color)

        content_row = 1

        # Show what was analyzed
        analyzed_splits = xapk_info.get('analyzed_splits', [])
        if analyzed_splits:
            label = ctk.CTkLabel(
                frame,
                text=f"✅ Analyzed: {', '.join(analyzed_splits)}",
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color="#4CAF50"
            )
            label.grid(row=content_row, column=0, sticky="w", padx=15, pady=5)
            content_row += 1

        # Show architecture APKs found
        arch_apks = xapk_info.get('arch_apks', [])
        if arch_apks:
            label = ctk.CTkLabel(
                frame,
                text=f"Architecture APKs: {', '.join(arch_apks)}",
                font=ctk.CTkFont(size=10),
                text_color="white"
            )
            label.grid(row=content_row, column=0, sticky="w", padx=15, pady=2)
            content_row += 1
        else:
            label = ctk.CTkLabel(
                frame,
                text="⚠️  Architecture APKs: NONE (x86/x86_64 only)",
                font=ctk.CTkFont(size=10),
                text_color="#FF9800"
            )
            label.grid(row=content_row, column=0, sticky="w", padx=15, pady=2)
            content_row += 1

        # Show total APKs
        manifest = xapk_info.get('manifest', {})
        total_size = manifest.get('total_size', 0)
        if total_size:
            size_mb = total_size / (1024 * 1024)
            label = ctk.CTkLabel(
                frame,
                text=f"Total XAPK Size: {size_mb:.1f}M",
                font=ctk.CTkFont(size=10),
                text_color="gray"
            )
            label.grid(row=content_row, column=0, sticky="w", padx=15, pady=2)
            content_row += 1

        # Show warnings
        warnings = xapk_info.get('warnings', [])
        if warnings:
            # Add separator
            separator = ctk.CTkFrame(frame, height=1, fg_color="gray")
            separator.grid(row=content_row, column=0, sticky="ew", padx=15, pady=10)
            content_row += 1

            warning_label = ctk.CTkLabel(
                frame,
                text="⚠️  WARNINGS:",
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color="#FF9800"
            )
            warning_label.grid(row=content_row, column=0, sticky="w", padx=15, pady=5)
            content_row += 1

            for warning in warnings:
                warning_text = ctk.CTkLabel(
                    frame,
                    text=warning,
                    font=ctk.CTkFont(size=10),
                    text_color="#FF9800",
                    wraplength=850,
                    anchor="w",
                    justify="left"
                )
                warning_text.grid(row=content_row, column=0, sticky="w", padx=25, pady=2)
                content_row += 1

    def _display_app_info(self, row):
        """Display app information section."""
        frame = self._create_section_frame(row, "App Information", "#1976D2")

        info_row = 1

        # Key information to display
        key_fields = [
            ('app_name', 'Name'),
            ('package_name', 'Package'),
            ('version_name', 'Version'),
            ('version_code', 'Version Code'),
            ('apk_size_formatted', 'APK Size'),
            ('min_sdk', 'Min SDK'),
            ('target_sdk', 'Target SDK')
        ]

        for key, label in key_fields:
            if key in self.app_metadata:
                value = self.app_metadata[key]
                self._add_info_row(frame, info_row, label, str(value))
                info_row += 1

    def _display_pdf_libraries(self, row, pdf_libs):
        """Display PDF libraries with special highlighting."""
        frame = self._create_section_frame(row, f"📄 PDF LIBRARIES ({len(pdf_libs)})", "#FF5722", highlight=True)

        if not pdf_libs:
            ctk.CTkLabel(
                frame,
                text="No PDF libraries detected",
                font=ctk.CTkFont(size=11),
                text_color="gray"
            ).grid(row=1, column=0, sticky="w", padx=15, pady=10)
            return

        lib_row = 1
        for lib in pdf_libs:
            lib_frame = ctk.CTkFrame(frame, fg_color="#2B2B2B", corner_radius=8, border_width=2, border_color="#FF5722")
            lib_frame.grid(row=lib_row, column=0, sticky="ew", padx=15, pady=8)
            lib_frame.grid_columnconfigure(0, weight=1)

            # Library name and confidence
            header_frame = ctk.CTkFrame(lib_frame, fg_color="transparent")
            header_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 5))

            ctk.CTkLabel(
                header_frame,
                text=lib['name'],
                font=ctk.CTkFont(size=14, weight="bold"),
                text_color="#FF5722"
            ).pack(side="left")

            confidence = lib.get('confidence', 0)
            color = self._get_confidence_color(confidence)
            ctk.CTkLabel(
                header_frame,
                text=f"{confidence}%",
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=color
            ).pack(side="right")

            # Description
            current_row = 1
            if lib.get('description'):
                ctk.CTkLabel(
                    lib_frame,
                    text=lib['description'],
                    font=ctk.CTkFont(size=10),
                    text_color="gray"
                ).grid(row=current_row, column=0, sticky="w", padx=10, pady=(0, 5))
                current_row += 1

            # Check if this is PSPDFKit (our own product) vs competitor
            is_pspdfkit = lib['name'].lower() == 'pspdfkit'

            # Version info (if detected)
            if lib.get('version'):
                version_info = lib['version']
                version_text = f"📦 Version: {version_info.get('version', 'Unknown')}"
                if version_info.get('status'):
                    version_text += f" ({version_info['status']})"

                version_color = "#4CAF50" if version_info.get('status') == 'Recent' else "#FF9800"

                ctk.CTkLabel(
                    lib_frame,
                    text=version_text,
                    font=ctk.CTkFont(size=10, weight="bold"),
                    text_color=version_color
                ).grid(row=current_row, column=0, sticky="w", padx=10, pady=(0, 5))
                current_row += 1

            # Features (if detected) - ONLY show for competitors, not for PSPDFKit
            if lib.get('features') and not is_pspdfkit:
                features = lib['features']
                features_frame = ctk.CTkFrame(lib_frame, fg_color="#1E1E1E", corner_radius=4)
                features_frame.grid(row=current_row, column=0, sticky="ew", padx=10, pady=(0, 5))
                current_row += 1

                ctk.CTkLabel(
                    features_frame,
                    text=f"🔧 Features Detected ({len(features)}):",
                    font=ctk.CTkFont(size=9, weight="bold"),
                    text_color="#2196F3"
                ).grid(row=0, column=0, sticky="w", padx=8, pady=(6, 3))

                for idx, feature in enumerate(features[:5], 1):  # Show first 5
                    tier_indicator = "⭐" if feature['tier'] == 'premium' else "📘"
                    feature_text = f"{tier_indicator} {feature['name']}"
                    if feature['tier'] == 'premium':
                        feature_text += " (Premium)"

                    ctk.CTkLabel(
                        features_frame,
                        text=feature_text,
                        font=ctk.CTkFont(size=8),
                        text_color="white"
                    ).grid(row=idx, column=0, sticky="w", padx=15, pady=1)

                if len(features) > 5:
                    ctk.CTkLabel(
                        features_frame,
                        text=f"... and {len(features) - 5} more features",
                        font=ctk.CTkFont(size=8),
                        text_color="gray"
                    ).grid(row=6, column=0, sticky="w", padx=15, pady=(1, 6))
                else:
                    # Add bottom padding for last feature
                    features_frame.grid_configure(pady=(0, 8))

            # For PSPDFKit, add note about internal verification
            if is_pspdfkit and lib.get('features'):
                ctk.CTkLabel(
                    lib_frame,
                    text="ℹ️  Feature details available via internal licensing database",
                    font=ctk.CTkFont(size=9),
                    text_color="#888888"
                ).grid(row=current_row, column=0, sticky="w", padx=10, pady=(0, 5))
                current_row += 1

            # Matched signatures
            if lib.get('matched_signatures'):
                sigs_text = "Detected: " + ", ".join(lib['matched_signatures'][:3])
                if len(lib['matched_signatures']) > 3:
                    sigs_text += f" (+{len(lib['matched_signatures']) - 3} more)"

                ctk.CTkLabel(
                    lib_frame,
                    text=sigs_text,
                    font=ctk.CTkFont(size=9),
                    text_color="#A0A0A0"
                ).grid(row=current_row, column=0, sticky="w", padx=10, pady=(0, 10))

            lib_row += 1

    def _display_document_viewing_solutions(self, row, solutions):
        """Display non-commercial document viewing solutions."""
        frame = self._create_section_frame(
            row,
            f"ℹ️  OTHER DOCUMENT VIEWING SOLUTIONS ({len(solutions)})",
            "#2196F3"
        )

        info_label = ctk.CTkLabel(
            frame,
            text="These are non-commercial solutions (plugins, system APIs, web-based viewers):",
            font=ctk.CTkFont(size=9),
            text_color="gray"
        )
        info_label.grid(row=1, column=0, sticky="w", padx=15, pady=(5, 10))

        solution_row = 2
        for solution in solutions:
            sol_frame = ctk.CTkFrame(frame, fg_color="#2B2B2B", corner_radius=6)
            sol_frame.grid(row=solution_row, column=0, sticky="ew", padx=15, pady=5)
            sol_frame.grid_columnconfigure(0, weight=1)

            # Solution name and type
            header_frame = ctk.CTkFrame(sol_frame, fg_color="transparent")
            header_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=(8, 3))

            ctk.CTkLabel(
                header_frame,
                text=solution['name'],
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color="#2196F3"
            ).pack(side="left")

            ctk.CTkLabel(
                header_frame,
                text=solution['type'],
                font=ctk.CTkFont(size=9),
                text_color="#888888"
            ).pack(side="right")

            # Description
            ctk.CTkLabel(
                sol_frame,
                text=solution['description'],
                font=ctk.CTkFont(size=9),
                text_color="gray",
                wraplength=800,
                anchor="w",
                justify="left"
            ).grid(row=1, column=0, sticky="w", padx=10, pady=(0, 3))

            # Matched signatures
            if solution.get('matched'):
                matched_text = "Found: " + ", ".join(solution['matched'][:2])
                if len(solution['matched']) > 2:
                    matched_text += f" (+{len(solution['matched']) - 2} more)"

                ctk.CTkLabel(
                    sol_frame,
                    text=matched_text,
                    font=ctk.CTkFont(size=8),
                    text_color="#666666"
                ).grid(row=2, column=0, sticky="w", padx=10, pady=(0, 8))

            solution_row += 1

    def _display_native_libraries(self, row, native_libs):
        """Display native libraries with architecture details."""
        # Group by library name first to get unique count
        lib_groups = {}
        for lib in native_libs:
            name = lib['name']
            if name not in lib_groups:
                lib_groups[name] = []
            lib_groups[name].append(lib)

        # Create frame with unique library count
        if native_libs:
            frame = self._create_section_frame(row, f"Native Libraries ({len(lib_groups)} unique, {len(native_libs)} total)", "#4CAF50")
        else:
            frame = self._create_section_frame(row, "Native Libraries (0)", "#4CAF50")

        if not native_libs:
            ctk.CTkLabel(
                frame,
                text="No native libraries (.so files) found in this app.",
                font=ctk.CTkFont(size=11),
                text_color="gray"
            ).grid(row=1, column=0, sticky="w", padx=15, pady=10)
            return

        lib_row = 1
        count = 0
        for name, variants in sorted(lib_groups.items()):
            if count >= 50:  # Increased limit
                remaining = len(lib_groups) - count
                ctk.CTkLabel(
                    frame,
                    text=f"... and {remaining} more native libraries",
                    font=ctk.CTkFont(size=10),
                    text_color="gray"
                ).grid(row=lib_row, column=0, sticky="w", padx=15, pady=5)
                break

            lib_frame = ctk.CTkFrame(frame, fg_color="#2B2B2B", corner_radius=6)
            lib_frame.grid(row=lib_row, column=0, sticky="ew", padx=15, pady=4)
            lib_frame.grid_columnconfigure(1, weight=1)

            # Library name with file count
            name_text = f"{name}"
            if len(variants) > 1:
                name_text += f" ({len(variants)} architectures)"

            ctk.CTkLabel(
                lib_frame,
                text=name_text,
                font=ctk.CTkFont(size=11, weight="bold")
            ).grid(row=0, column=0, sticky="w", padx=10, pady=8)

            # Show architectures and sizes
            archs_text = ", ".join([f"{v['architecture']} ({v['size_formatted']})" for v in variants])
            ctk.CTkLabel(
                lib_frame,
                text=archs_text,
                font=ctk.CTkFont(size=9),
                text_color="gray"
            ).grid(row=0, column=1, sticky="e", padx=10, pady=8)

            lib_row += 1
            count += 1

    def _display_package_summary(self, row, package_counts):
        """Display Java packages summary."""
        frame = self._create_section_frame(row, "Java Packages", "#00BCD4")

        if not package_counts:
            ctk.CTkLabel(
                frame,
                text="No Java packages found.",
                font=ctk.CTkFont(size=11),
                text_color="gray"
            ).grid(row=1, column=0, sticky="w", padx=15, pady=10)
            return

        # Get top-level packages
        top_packages = {}
        for pkg, count in package_counts.items():
            # Get first two parts of package name
            parts = pkg.split('.')
            if len(parts) >= 2:
                top = '.'.join(parts[:2])
                top_packages[top] = top_packages.get(top, 0) + count

        # Display top packages
        pkg_row = 1
        for pkg, count in sorted(top_packages.items(), key=lambda x: x[1], reverse=True)[:20]:
            pkg_frame = ctk.CTkFrame(frame, fg_color="transparent")
            pkg_frame.grid(row=pkg_row, column=0, sticky="ew", padx=15, pady=2)
            pkg_frame.grid_columnconfigure(0, weight=1)

            ctk.CTkLabel(
                pkg_frame,
                text=f"• {pkg}",
                font=ctk.CTkFont(size=10)
            ).grid(row=0, column=0, sticky="w")

            ctk.CTkLabel(
                pkg_frame,
                text=f"({count} classes)",
                font=ctk.CTkFont(size=9),
                text_color="gray"
            ).grid(row=0, column=1, sticky="e")

            pkg_row += 1

        if len(top_packages) > 20:
            ctk.CTkLabel(
                frame,
                text=f"... and {len(top_packages) - 20} more packages",
                font=ctk.CTkFont(size=9),
                text_color="gray"
            ).grid(row=pkg_row, column=0, sticky="w", padx=15, pady=5)

    def _display_google_firebase(self, row, gps_libs, firebase_libs):
        """Display Google Play Services and Firebase libraries."""
        total = len(gps_libs) + len(firebase_libs)
        frame = self._create_section_frame(row, f"Google Play Services & Firebase ({total})", "#4285F4")

        lib_row = 1

        if gps_libs:
            for lib in gps_libs:
                self._add_library_row(frame, lib_row, lib)
                lib_row += 1

        if firebase_libs:
            for lib in firebase_libs:
                self._add_library_row(frame, lib_row, lib)
                lib_row += 1

    def _display_androidx(self, row, androidx_libs):
        """Display AndroidX libraries."""
        frame = self._create_section_frame(row, f"AndroidX/Jetpack Libraries ({len(androidx_libs)})", "#3DDC84")

        lib_row = 1
        for lib in androidx_libs[:30]:  # Limit display
            self._add_library_row(frame, lib_row, lib)
            lib_row += 1

        if len(androidx_libs) > 30:
            ctk.CTkLabel(
                frame,
                text=f"... and {len(androidx_libs) - 30} more AndroidX libraries",
                font=ctk.CTkFont(size=9),
                text_color="gray"
            ).grid(row=lib_row, column=0, sticky="w", padx=15, pady=5)

    def _display_kotlin(self, row, kotlin_libs):
        """Display Kotlin libraries."""
        frame = self._create_section_frame(row, f"Kotlin Libraries ({len(kotlin_libs)})", "#7F52FF")

        lib_row = 1
        for lib in kotlin_libs:
            self._add_library_row(frame, lib_row, lib)
            lib_row += 1

    def _display_category_section(self, row, title, libs, color):
        """Display a generic category section."""
        frame = self._create_section_frame(row, f"{title} ({len(libs)})", color)

        lib_row = 1
        for lib in libs:
            self._add_library_row(frame, lib_row, lib)
            lib_row += 1

    def _display_permissions(self, row, permissions):
        """Display permissions."""
        frame = self._create_section_frame(row, f"Permissions ({len(permissions)})", "#FFC107")

        perm_row = 1
        for perm in permissions[:30]:  # Limit display
            ctk.CTkLabel(
                frame,
                text=f"• {perm}",
                font=ctk.CTkFont(size=9)
            ).grid(row=perm_row, column=0, sticky="w", padx=15, pady=1)
            perm_row += 1

        if len(permissions) > 30:
            ctk.CTkLabel(
                frame,
                text=f"... and {len(permissions) - 30} more permissions",
                font=ctk.CTkFont(size=9),
                text_color="gray"
            ).grid(row=perm_row, column=0, sticky="w", padx=15, pady=5)

    def _display_hardware_features(self, row, features):
        """Display hardware features."""
        frame = self._create_section_frame(row, f"Hardware Features ({len(features)})", "#607D8B")

        feat_row = 1
        for feat in features:
            ctk.CTkLabel(
                frame,
                text=f"• {feat}",
                font=ctk.CTkFont(size=9)
            ).grid(row=feat_row, column=0, sticky="w", padx=15, pady=1)
            feat_row += 1

    def _display_assets_resources(self, row, assets, resources):
        """Display assets and resources summary."""
        frame = self._create_section_frame(row, "Assets & Resources Summary", "#8BC34A")

        info_row = 1

        if assets:
            self._add_info_row(frame, info_row, "Assets", f"{assets.get('count', 0)} files ({assets.get('size_formatted', '0')})")
            info_row += 1

        if resources:
            self._add_info_row(frame, info_row, "Resources", f"{resources.get('count', 0)} files ({resources.get('size_formatted', '0')})")
            info_row += 1

    def _create_section_frame(self, row, title, color, highlight=False):
        """Create a section frame with header."""
        frame = ctk.CTkFrame(self, fg_color="#1A1A1A" if not highlight else "#2B1F1F", corner_radius=10)
        frame.grid(row=row, column=0, sticky="ew", padx=10, pady=8)
        frame.grid_columnconfigure(0, weight=1)

        # Header
        header_frame = ctk.CTkFrame(frame, fg_color=color, corner_radius=8)
        header_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)

        ctk.CTkLabel(
            header_frame,
            text=title,
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="white"
        ).pack(padx=15, pady=8)

        return frame

    def _add_info_row(self, frame, row, label, value):
        """Add an info row to a frame."""
        row_frame = ctk.CTkFrame(frame, fg_color="transparent")
        row_frame.grid(row=row, column=0, sticky="ew", padx=15, pady=2)
        row_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            row_frame,
            text=f"{label}:",
            font=ctk.CTkFont(weight="bold", size=10)
        ).grid(row=0, column=0, sticky="w")

        ctk.CTkLabel(
            row_frame,
            text=str(value),
            font=ctk.CTkFont(size=10)
        ).grid(row=0, column=1, sticky="w", padx=(10, 0))

    def _add_library_row(self, frame, row, lib):
        """Add a library row to a frame."""
        row_frame = ctk.CTkFrame(frame, fg_color="transparent")
        row_frame.grid(row=row, column=0, sticky="ew", padx=15, pady=2)
        row_frame.grid_columnconfigure(0, weight=1)

        name = lib.get('name', 'Unknown')
        version = lib.get('version', '')
        description = lib.get('description', '')

        display_text = f"• {name}"
        if version and version != "Unknown":
            display_text += f" ({version})"

        ctk.CTkLabel(
            row_frame,
            text=display_text,
            font=ctk.CTkFont(size=10, weight="bold")
        ).grid(row=0, column=0, sticky="w")

        # Add description if available
        if description:
            ctk.CTkLabel(
                row_frame,
                text=f"  {description}",
                font=ctk.CTkFont(size=9),
                text_color="gray",
                wraplength=850,
                anchor="w",
                justify="left"
            ).grid(row=1, column=0, sticky="w", padx=(10, 0))

    def _get_confidence_color(self, confidence):
        """Get color based on confidence level."""
        if confidence >= 80:
            return "#4CAF50"  # Green
        elif confidence >= 50:
            return "#FF9800"  # Orange
        else:
            return "#F44336"  # Red

    def clear_results(self):
        """Clear all results from the panel."""
        for widget in self.winfo_children():
            widget.destroy()

    def _export_json(self):
        """Export results as JSON."""
        try:
            from tkinter import filedialog

            file_path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )

            if file_path:
                export_data = {
                    'app_metadata': self.app_metadata,
                    'detected_libraries': self.detected_libraries
                }

                with open(file_path, 'w') as f:
                    json.dump(export_data, f, indent=2, default=str)

                messagebox.showinfo("Success", f"Results exported to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export JSON: {str(e)}")

    def _export_csv(self):
        """Export results as CSV."""
        try:
            from tkinter import filedialog

            file_path = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
            )

            if file_path:
                with open(file_path, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Category', 'Library Name', 'Version', 'Details'])

                    # Write detected libraries by category
                    for category, libs in self.detected_libraries.items():
                        if isinstance(libs, list):
                            for lib in libs:
                                if isinstance(lib, dict):
                                    name = lib.get('name', '')
                                    version = lib.get('version', '')
                                    details = lib.get('description', lib.get('package', ''))
                                    writer.writerow([category, name, version, details])

                messagebox.showinfo("Success", f"Results exported to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export CSV: {str(e)}")

    def _copy_to_clipboard(self):
        """Copy results summary to clipboard."""
        try:
            summary = self._generate_text_summary()
            self.clipboard_clear()
            self.clipboard_append(summary)
            messagebox.showinfo("Success", "Results copied to clipboard!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy to clipboard: {str(e)}")

    def _generate_text_summary(self) -> str:
        """Generate a text summary of results."""
        lines = []
        lines.append("=" * 80)
        lines.append("LIBRARY & SDK ANALYSIS REPORT")
        lines.append("=" * 80)
        lines.append("")

        # XAPK Analysis Info (if present)
        if 'xapk_info' in self.app_metadata:
            xapk_info = self.app_metadata['xapk_info']
            lines.append("📦 XAPK ANALYSIS BREAKDOWN")
            lines.append("-" * 80)

            analyzed_splits = xapk_info.get('analyzed_splits', [])
            if analyzed_splits:
                lines.append(f"✅ Analyzed: {', '.join(analyzed_splits)}")

            arch_apks = xapk_info.get('arch_apks', [])
            if arch_apks:
                lines.append(f"Architecture APKs: {', '.join(arch_apks)}")
            else:
                lines.append("⚠️  Architecture APKs: NONE (x86/x86_64 only - INCOMPLETE XAPK)")

            manifest = xapk_info.get('manifest', {})
            if manifest.get('total_size'):
                size_mb = manifest['total_size'] / (1024 * 1024)
                lines.append(f"Total XAPK Size: {size_mb:.1f}M")

            # Show warnings
            warnings = xapk_info.get('warnings', [])
            if warnings:
                lines.append("")
                lines.append("⚠️  WARNINGS:")
                for warning in warnings:
                    lines.append(f"  {warning}")

            lines.append("")

        # App info
        lines.append("APP INFORMATION")
        lines.append("-" * 80)
        if 'app_name' in self.app_metadata:
            lines.append(f"Name: {self.app_metadata['app_name']}")
        if 'package_name' in self.app_metadata:
            lines.append(f"Package: {self.app_metadata['package_name']}")
        if 'version_name' in self.app_metadata:
            lines.append(f"Version: {self.app_metadata['version_name']}")
        if 'version_code' in self.app_metadata:
            lines.append(f"Version Code: {self.app_metadata['version_code']}")
        if 'min_sdk' in self.app_metadata:
            lines.append(f"Min SDK: {self.app_metadata['min_sdk']}")
        if 'target_sdk' in self.app_metadata:
            lines.append(f"Target SDK: {self.app_metadata['target_sdk']}")
        if 'apk_size_formatted' in self.app_metadata:
            lines.append(f"Size: {self.app_metadata['apk_size_formatted']}")
        lines.append("")

        # PDF Libraries (highlighted section)
        pdf_libs = self.detected_libraries.get('pdf_libraries', [])
        if pdf_libs:
            lines.append("🔴 " + "=" * 76 + " 🔴")
            lines.append(f"📄 PDF LIBRARIES ({len(pdf_libs)}) - DETECTED!")
            lines.append("🔴 " + "=" * 76 + " 🔴")
            for lib in pdf_libs:
                lines.append(f"  • {lib['name']} - Confidence: {lib.get('confidence', 0)}%")
                if 'description' in lib:
                    lines.append(f"    {lib['description']}")

                # Check if this is PSPDFKit vs competitor
                is_pspdfkit = lib['name'].lower() == 'pspdfkit'

                # Version info
                if 'version' in lib:
                    version_info = lib['version']
                    version_text = f"    📦 Version: {version_info.get('version', 'Unknown')}"
                    if version_info.get('status'):
                        version_text += f" ({version_info['status']})"
                    lines.append(version_text)

                # Features - ONLY show for competitors, not for PSPDFKit
                if 'features' in lib and not is_pspdfkit:
                    features = lib['features']
                    lines.append(f"    🔧 Features Detected ({len(features)}):")
                    for feature in features[:5]:
                        tier_mark = "⭐ PREMIUM" if feature['tier'] == 'premium' else "📘"
                        lines.append(f"       {tier_mark} {feature['name']}")
                    if len(features) > 5:
                        lines.append(f"       ... and {len(features) - 5} more features")

                # For PSPDFKit, add note about internal verification
                if is_pspdfkit and 'features' in lib:
                    lines.append(f"    ℹ️  Feature details available via internal licensing database")

                if 'matched_signatures' in lib:
                    lines.append(f"    Matched: {', '.join(lib['matched_signatures'][:3])}")
                lines.append("")
            lines.append("")
        else:
            lines.append("PDF LIBRARIES")
            lines.append("-" * 80)
            lines.append("  No commercial PDF SDKs detected (checked 24 libraries)")
            lines.append("")

        # Document Viewing Solutions
        doc_solutions = self.detected_libraries.get('document_viewing_solutions', [])
        if doc_solutions:
            lines.append("ℹ️  OTHER DOCUMENT VIEWING SOLUTIONS")
            lines.append("-" * 80)
            lines.append("Non-commercial solutions (plugins, system APIs, web-based viewers):")
            lines.append("")
            for solution in doc_solutions:
                lines.append(f"  • {solution['name']}")
                lines.append(f"    Type: {solution['type']}")
                lines.append(f"    {solution['description']}")
                if solution.get('matched'):
                    lines.append(f"    Found: {', '.join(solution['matched'][:2])}")
                lines.append("")

        # All library categories
        categories = [
            ('google_play_services', 'Google Play Services'),
            ('firebase', 'Firebase'),
            ('androidx', 'AndroidX'),
            ('kotlin', 'Kotlin'),
            ('analytics', 'Analytics'),
            ('crash_reporting', 'Crash Reporting'),
            ('networking', 'Networking'),
            ('ui_libraries', 'UI Libraries'),
            ('dependency_injection', 'Dependency Injection'),
            ('social', 'Social SDKs')
        ]

        for key, title in categories:
            libs = self.detected_libraries.get(key, [])
            if libs:
                lines.append(f"{title.upper()} ({len(libs)})")
                lines.append("-" * 80)
                for lib in libs[:15]:  # Show up to 15
                    name = lib.get('name', 'Unknown')
                    version = lib.get('version', '')
                    if version and version != 'Unknown':
                        lines.append(f"  • {name} ({version})")
                    else:
                        lines.append(f"  • {name}")
                if len(libs) > 15:
                    lines.append(f"  ... and {len(libs) - 15} more")
                lines.append("")

        # Native Libraries
        native_libs = self.app_metadata.get('native_libs_detailed', [])
        if native_libs:
            # Group by library name
            lib_groups = {}
            for lib in native_libs:
                name = lib['name']
                if name not in lib_groups:
                    lib_groups[name] = []
                lib_groups[name].append(lib)

            lines.append(f"NATIVE LIBRARIES ({len(lib_groups)} unique, {len(native_libs)} total)")
            lines.append("-" * 80)
            for name, libs in sorted(lib_groups.items())[:30]:  # Show up to 30
                archs = [lib['architecture'] for lib in libs]
                lines.append(f"  • {name} [{', '.join(archs)}]")
            if len(lib_groups) > 30:
                lines.append(f"  ... and {len(lib_groups) - 30} more")
            lines.append("")
        else:
            lines.append("NATIVE LIBRARIES")
            lines.append("-" * 80)
            lines.append("  No native libraries found")
            lines.append("")

        # Permissions
        permissions = self.app_metadata.get('permissions', [])
        if permissions:
            lines.append(f"PERMISSIONS ({len(permissions)})")
            lines.append("-" * 80)
            for perm in permissions[:20]:  # Show up to 20
                lines.append(f"  • {perm}")
            if len(permissions) > 20:
                lines.append(f"  ... and {len(permissions) - 20} more")
            lines.append("")

        # Statistics
        lines.append("STATISTICS")
        lines.append("-" * 80)
        total_libs = sum(len(v) for k, v in self.detected_libraries.items() if isinstance(v, list))
        lines.append(f"Total Libraries Detected: {total_libs}")
        if 'permissions_count' in self.app_metadata:
            lines.append(f"Total Permissions: {self.app_metadata['permissions_count']}")
        if 'features_count' in self.app_metadata:
            lines.append(f"Total Features: {self.app_metadata['features_count']}")
        lines.append("")

        lines.append("=" * 80)
        lines.append("Generated by Library & SDK Analyzer")
        lines.append("=" * 80)

        return "\n".join(lines)
