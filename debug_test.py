"""Debug script to test iOS app metadata fetching."""

import sys
sys.path.insert(0, '.')

from src.downloaders.ipa_downloader import IPADownloader

# Test with the Sprocket Sports app
app_id = "1548746450"

print("Testing iOS app metadata fetching...")
downloader = IPADownloader()

try:
    metadata = downloader.get_app_metadata(app_id)
    print("\nMetadata retrieved successfully!")
    print("\nMetadata contents:")
    for key, value in sorted(metadata.items()):
        print(f"  {key}: {value} (type: {type(value).__name__})")

    # Check if any values are not strings
    non_string_values = {k: v for k, v in metadata.items() if not isinstance(v, str)}
    if non_string_values:
        print("\nWARNING: Non-string values found:")
        for k, v in non_string_values.items():
            print(f"  {k}: {v} (type: {type(v).__name__})")
    else:
        print("\nAll values are strings - Good!")

except Exception as e:
    import traceback
    print(f"\nError: {e}")
    print("\nFull traceback:")
    traceback.print_exc()
