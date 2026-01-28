"""
Analysis Cache - Stores and retrieves previous analysis results
"""

import sqlite3
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict


class AnalysisCache:
    """Manages persistent storage of analysis results."""

    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize the analysis cache.

        Args:
            db_path: Path to SQLite database file. Defaults to ~/.pdf_detector_cache.db
        """
        if db_path is None:
            db_path = str(Path.home() / ".pdf_detector_cache.db")

        self.db_path = db_path
        self._init_database()

    def _init_database(self):
        """Initialize the database schema."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Create analyses table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS analyses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    package_name TEXT NOT NULL,
                    version_name TEXT,
                    version_code TEXT,
                    app_name TEXT,
                    platform TEXT NOT NULL,
                    analyzed_date TEXT NOT NULL,
                    file_path TEXT,
                    app_metadata TEXT NOT NULL,
                    detected_libraries TEXT NOT NULL,
                    UNIQUE(package_name, version_name, version_code)
                )
            """)

            # Create index for faster lookups
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_package_name
                ON analyses(package_name)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_analyzed_date
                ON analyses(analyzed_date DESC)
            """)

            conn.commit()

    def save_analysis(
        self,
        package_name: str,
        app_metadata: Dict,
        detected_libraries: Dict,
        platform: str,
        file_path: Optional[str] = None
    ) -> bool:
        """
        Save an analysis to the cache.

        Args:
            package_name: App package/bundle identifier
            app_metadata: Full app metadata dictionary
            detected_libraries: Detected libraries dictionary
            platform: 'android' or 'ios'
            file_path: Original file path (optional)

        Returns:
            True if saved successfully, False otherwise
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Extract key fields
                version_name = app_metadata.get('version_name', 'Unknown')
                version_code = str(app_metadata.get('version_code', ''))
                app_name = app_metadata.get('app_name', 'Unknown')
                analyzed_date = datetime.now().isoformat()

                # Serialize data
                metadata_json = json.dumps(app_metadata, default=str)
                libraries_json = json.dumps(detected_libraries, default=str)

                # Insert or replace
                cursor.execute("""
                    INSERT OR REPLACE INTO analyses
                    (package_name, version_name, version_code, app_name, platform,
                     analyzed_date, file_path, app_metadata, detected_libraries)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    package_name,
                    version_name,
                    version_code,
                    app_name,
                    platform,
                    analyzed_date,
                    file_path,
                    metadata_json,
                    libraries_json
                ))

                conn.commit()
                return True

        except Exception as e:
            print(f"Error saving analysis to cache: {e}")
            return False

    def get_analysis(
        self,
        package_name: str,
        version_name: Optional[str] = None,
        version_code: Optional[str] = None
    ) -> Optional[Dict]:
        """
        Retrieve a cached analysis.

        Args:
            package_name: App package/bundle identifier
            version_name: Specific version (optional)
            version_code: Specific version code (optional)

        Returns:
            Dictionary with analysis data, or None if not found
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                if version_name and version_code:
                    # Exact match
                    cursor.execute("""
                        SELECT id, package_name, version_name, version_code, app_name,
                               platform, analyzed_date, file_path, app_metadata, detected_libraries
                        FROM analyses
                        WHERE package_name = ? AND version_name = ? AND version_code = ?
                        ORDER BY analyzed_date DESC
                        LIMIT 1
                    """, (package_name, version_name, version_code))
                else:
                    # Most recent for this package
                    cursor.execute("""
                        SELECT id, package_name, version_name, version_code, app_name,
                               platform, analyzed_date, file_path, app_metadata, detected_libraries
                        FROM analyses
                        WHERE package_name = ?
                        ORDER BY analyzed_date DESC
                        LIMIT 1
                    """, (package_name,))

                row = cursor.fetchone()

                if row:
                    return {
                        'id': row[0],
                        'package_name': row[1],
                        'version_name': row[2],
                        'version_code': row[3],
                        'app_name': row[4],
                        'platform': row[5],
                        'analyzed_date': row[6],
                        'file_path': row[7],
                        'app_metadata': json.loads(row[8]),
                        'detected_libraries': json.loads(row[9])
                    }

                return None

        except Exception as e:
            print(f"Error retrieving analysis from cache: {e}")
            return None

    def get_all_analyses(self, limit: int = 50) -> List[Dict]:
        """
        Get all cached analyses, most recent first.

        Args:
            limit: Maximum number of results

        Returns:
            List of analysis summaries
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                cursor.execute("""
                    SELECT id, package_name, version_name, app_name, platform, analyzed_date
                    FROM analyses
                    ORDER BY analyzed_date DESC
                    LIMIT ?
                """, (limit,))

                results = []
                for row in cursor.fetchall():
                    results.append({
                        'id': row[0],
                        'package_name': row[1],
                        'version_name': row[2],
                        'app_name': row[3],
                        'platform': row[4],
                        'analyzed_date': row[5]
                    })

                return results

        except Exception as e:
            print(f"Error getting all analyses: {e}")
            return []

    def delete_analysis(self, analysis_id: int) -> bool:
        """
        Delete an analysis from cache.

        Args:
            analysis_id: ID of the analysis to delete

        Returns:
            True if deleted successfully
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,))
                conn.commit()
                return True

        except Exception as e:
            print(f"Error deleting analysis: {e}")
            return False

    def clear_all(self) -> bool:
        """
        Clear all cached analyses.

        Returns:
            True if cleared successfully
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM analyses")
                conn.commit()
                return True

        except Exception as e:
            print(f"Error clearing cache: {e}")
            return False

    def get_stats(self) -> Dict:
        """
        Get cache statistics.

        Returns:
            Dictionary with stats
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                cursor.execute("SELECT COUNT(*) FROM analyses")
                total = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(DISTINCT package_name) FROM analyses")
                unique_apps = cursor.fetchone()[0]

                cursor.execute("""
                    SELECT platform, COUNT(*)
                    FROM analyses
                    GROUP BY platform
                """)
                by_platform = dict(cursor.fetchall())

                return {
                    'total_analyses': total,
                    'unique_apps': unique_apps,
                    'by_platform': by_platform
                }

        except Exception as e:
            print(f"Error getting stats: {e}")
            return {
                'total_analyses': 0,
                'unique_apps': 0,
                'by_platform': {}
            }
