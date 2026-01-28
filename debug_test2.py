"""More detailed debug script."""

import sys
sys.path.insert(0, '.')

import requests

# Test with the Sprocket Sports app
app_id = "1548746450"

print("Testing iTunes API directly...")

try:
    url = f"https://itunes.apple.com/lookup?id={app_id}"
    response = requests.get(url, timeout=10)
    response.raise_for_status()

    data = response.json()

    if data.get('resultCount', 0) == 0:
        print("App not found")
    else:
        result = data['results'][0]

        print("\nRaw iTunes API response keys and values:")
        for key in sorted(result.keys()):
            value = result[key]
            print(f"  {key}: {repr(value)} (type: {type(value).__name__})")

        print("\n\nNow testing individual conversions:")

        print("\n1. Testing genres conversion...")
        genres = result.get('genres', [])
        print(f"   genres raw: {repr(genres)} (type: {type(genres).__name__})")
        if genres:
            print(f"   First genre: {repr(genres[0])} (type: {type(genres[0]).__name__})")
            genres_str = ', '.join([str(g) for g in genres])
            print(f"   genres joined: {genres_str}")

        print("\n2. Testing all conversions...")
        try:
            metadata = {
                'name': str(result.get('trackName', 'Unknown')),
                'app_id': str(app_id),
                'bundle_id': str(result.get('bundleId', 'Unknown')),
                'version': str(result.get('version', 'Unknown')),
                'developer': str(result.get('artistName', 'Unknown')),
                'rating': str(result.get('averageUserRating', 0)),
                'description': str(result.get('description', '')),
                'icon_url': str(result.get('artworkUrl512', '')),
                'released': str(result.get('releaseDate', 'Unknown')),
                'price': str(result.get('formattedPrice', 'Unknown')),
                'genres': ', '.join([str(g) for g in genres]) if genres else 'Unknown'
            }
            print("   All conversions successful!")

        except Exception as e:
            import traceback
            print(f"   ERROR during conversion: {e}")
            traceback.print_exc()

except Exception as e:
    import traceback
    print(f"\nError: {e}")
    print("\nFull traceback:")
    traceback.print_exc()
