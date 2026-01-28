"""
Results Panel GUI Component
Displays analysis results and detected PDF libraries.
"""

import customtkinter as ctk
from typing import List, Dict, Optional
import json
import csv
from pathlib import Path

from ..detectors.pdf_detector import DetectedLibrary


class ResultsPanel(ctk.CTkScrollableFrame):
    """Panel to display analysis results."""

    def __init__(self, parent, **kwargs):
        """
        Initialize results panel.

        Args:
            parent: Parent widget
        """
        super().__init__(parent, **kwargs)

        self.app_metadata = {}
        self.detected_libraries = []

        # Configure grid
        self.grid_columnconfigure(0, weight=1)

    def display_results(self, app_metadata: Dict, detected_libraries: List[DetectedLibrary]):
        """
        Display analysis results.

        Args:
            app_metadata: App metadata dictionary
            detected_libraries: List of detected PDF libraries
        """
        # Clear previous results
        self.clear_results()

        self.app_metadata = app_metadata
        self.detected_libraries = detected_libraries

        row = 0

        # Display app metadata
        metadata_frame = ctk.CTkFrame(self)
        metadata_frame.grid(row=row, column=0, sticky="ew", padx=10, pady=10)
        metadata_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            metadata_frame,
            text="App Information",
            font=ctk.CTkFont(size=16, weight="bold")
        ).grid(row=0, column=0, columnspan=2, sticky="w", padx=10, pady=(10, 5))

        metadata_row = 1
        # Sort keys to ensure consistent ordering and prevent comparison issues
        sorted_keys = sorted([str(k) for k in app_metadata.keys()])

        for key in sorted_keys:
            if key not in ['description', 'icon_url', 'error']:
                value = app_metadata[key]
                # Format key
                display_key = key.replace('_', ' ').title()

                ctk.CTkLabel(
                    metadata_frame,
                    text=f"{display_key}:",
                    font=ctk.CTkFont(weight="bold")
                ).grid(row=metadata_row, column=0, sticky="w", padx=10, pady=2)

                # Handle list values
                if isinstance(value, (list, tuple)):
                    value_str = ', '.join([str(v) for v in value]) if value else 'None'
                else:
                    value_str = str(value)

                ctk.CTkLabel(
                    metadata_frame,
                    text=value_str
                ).grid(row=metadata_row, column=1, sticky="w", padx=10, pady=2)

                metadata_row += 1

        row += 1

        # Display detected libraries
        libraries_frame = ctk.CTkFrame(self)
        libraries_frame.grid(row=row, column=0, sticky="ew", padx=10, pady=10)
        libraries_frame.grid_columnconfigure(0, weight=1)

        header_text = f"Detected PDF Libraries ({len(detected_libraries)})"
        ctk.CTkLabel(
            libraries_frame,
            text=header_text,
            font=ctk.CTkFont(size=16, weight="bold")
        ).grid(row=0, column=0, sticky="w", padx=10, pady=(10, 5))

        if not detected_libraries:
            ctk.CTkLabel(
                libraries_frame,
                text="No PDF libraries detected in this app.",
                font=ctk.CTkFont(size=12),
                text_color="gray"
            ).grid(row=1, column=0, sticky="w", padx=10, pady=10)
        else:
            # Display each detected library
            for idx, lib in enumerate(detected_libraries):
                lib_frame = self._create_library_card(libraries_frame, lib, idx)
                lib_frame.grid(row=idx + 1, column=0, sticky="ew", padx=10, pady=5)

        row += 1

        # Add export buttons
        export_frame = ctk.CTkFrame(self)
        export_frame.grid(row=row, column=0, sticky="ew", padx=10, pady=10)

        ctk.CTkButton(
            export_frame,
            text="Export as JSON",
            command=self._export_json
        ).pack(side="left", padx=5, pady=10)

        ctk.CTkButton(
            export_frame,
            text="Export as CSV",
            command=self._export_csv
        ).pack(side="left", padx=5, pady=10)

        ctk.CTkButton(
            export_frame,
            text="Copy to Clipboard",
            command=self._copy_to_clipboard
        ).pack(side="left", padx=5, pady=10)

    def _create_library_card(self, parent, library: DetectedLibrary, index: int) -> ctk.CTkFrame:
        """
        Create a card widget for a detected library.

        Args:
            parent: Parent widget
            library: DetectedLibrary object
            index: Index number

        Returns:
            Frame widget
        """
        card = ctk.CTkFrame(parent, fg_color="gray20")
        card.grid_columnconfigure(0, weight=1)

        # Confidence color
        if library.confidence >= 80:
            confidence_color = "green"
        elif library.confidence >= 50:
            confidence_color = "orange"
        else:
            confidence_color = "red"

        # Header with name and confidence
        header_frame = ctk.CTkFrame(card, fg_color="transparent")
        header_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 5))
        header_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            header_frame,
            text=f"{index + 1}. {library.name}",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(side="left")

        ctk.CTkLabel(
            header_frame,
            text=f"{library.confidence:.1f}%",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=confidence_color
        ).pack(side="right")

        # Description
        if library.description:
            ctk.CTkLabel(
                card,
                text=library.description,
                font=ctk.CTkFont(size=11),
                text_color="gray"
            ).grid(row=1, column=0, sticky="w", padx=10, pady=2)

        # Detection methods
        methods_text = "Detection: " + ", ".join(library.detection_methods)
        ctk.CTkLabel(
            card,
            text=methods_text,
            font=ctk.CTkFont(size=11)
        ).grid(row=2, column=0, sticky="w", padx=10, pady=2)

        # Matched signatures
        if library.matched_signatures:
            signatures_text = "Signatures: " + ", ".join(library.matched_signatures[:3])
            if len(library.matched_signatures) > 3:
                signatures_text += f" (+{len(library.matched_signatures) - 3} more)"

            ctk.CTkLabel(
                card,
                text=signatures_text,
                font=ctk.CTkFont(size=10),
                text_color="lightblue"
            ).grid(row=3, column=0, sticky="w", padx=10, pady=2)

        # Locations (expandable)
        if library.locations:
            # Show first 2 locations
            locations_to_show = library.locations[:2]
            for i, location in enumerate(locations_to_show):
                ctk.CTkLabel(
                    card,
                    text=f"  • {location}",
                    font=ctk.CTkFont(size=10),
                    text_color="gray70"
                ).grid(row=4 + i, column=0, sticky="w", padx=10, pady=1)

            if len(library.locations) > 2:
                ctk.CTkLabel(
                    card,
                    text=f"  ... and {len(library.locations) - 2} more locations",
                    font=ctk.CTkFont(size=10),
                    text_color="gray50"
                ).grid(row=6, column=0, sticky="w", padx=10, pady=(1, 10))
        else:
            # Add bottom padding
            ctk.CTkLabel(card, text="").grid(row=4, column=0, pady=5)

        return card

    def clear_results(self):
        """Clear all displayed results."""
        for widget in self.winfo_children():
            widget.destroy()

        self.app_metadata = {}
        self.detected_libraries = []

    def _export_json(self):
        """Export results as JSON file."""
        if not self.detected_libraries:
            return

        # Create export data
        export_data = {
            'app_metadata': self.app_metadata,
            'detected_libraries': [
                {
                    'name': lib.name,
                    'description': lib.description,
                    'confidence': lib.confidence,
                    'detection_methods': lib.detection_methods,
                    'matched_signatures': lib.matched_signatures,
                    'locations': lib.locations
                }
                for lib in self.detected_libraries
            ]
        }

        # Save file dialog
        from tkinter import filedialog
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=f"{self.app_metadata.get('name', 'app')}_pdf_libraries.json"
        )

        if file_path:
            with open(file_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            print(f"Exported to {file_path}")

    def _export_csv(self):
        """Export results as CSV file."""
        if not self.detected_libraries:
            return

        # Save file dialog
        from tkinter import filedialog
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"{self.app_metadata.get('name', 'app')}_pdf_libraries.csv"
        )

        if file_path:
            with open(file_path, 'w', newline='') as f:
                writer = csv.writer(f)

                # Write header
                writer.writerow([
                    'Library Name',
                    'Description',
                    'Confidence (%)',
                    'Detection Methods',
                    'Matched Signatures',
                    'Locations'
                ])

                # Write data
                for lib in self.detected_libraries:
                    writer.writerow([
                        lib.name,
                        lib.description,
                        f"{lib.confidence:.1f}",
                        "; ".join(lib.detection_methods),
                        "; ".join(lib.matched_signatures),
                        "; ".join(lib.locations)
                    ])

            print(f"Exported to {file_path}")

    def _copy_to_clipboard(self):
        """Copy results to clipboard."""
        if not self.detected_libraries:
            return

        # Create text report
        lines = []
        lines.append(f"App: {self.app_metadata.get('name', 'Unknown')}")
        lines.append(f"Platform: {self.app_metadata.get('platform', 'Unknown')}")
        lines.append("")
        lines.append(f"Detected {len(self.detected_libraries)} PDF Libraries:")
        lines.append("")

        for idx, lib in enumerate(self.detected_libraries, 1):
            lines.append(f"{idx}. {lib.name} ({lib.confidence:.1f}%)")
            lines.append(f"   {lib.description}")
            lines.append(f"   Detection: {', '.join(lib.detection_methods)}")
            lines.append("")

        text = "\n".join(lines)

        # Copy to clipboard
        self.clipboard_clear()
        self.clipboard_append(text)
        print("Copied to clipboard!")
