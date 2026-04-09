# Asset-Indexe
Universal File Catalog with Cryptographic Deduplication Supports Local Storage, Cloud Drives (Google Drive, OneDrive, Backblaze), and Android

``` bash
# Install dependencies
pip install blake3 rich tqdm google-api-python-client google-auth-httplib2

# Optional: For Android support
pip install adb-shell

# Optional: For OneDrive/Backblaze (implement adapters)
pip install msal b2sdk
```

``` bash
# 1. Index local MacBook storage (with BLAKE3 hashing)
python asset_indexer.py --hash blake3 index local "MacBook-Pro" "/Users/username"

# 2. Quick scan (names/sizes only, no hashing)
python asset_indexer.py --quick index local "MacBook-Quick" "/Users/username"

# 3. Index Android device via ADB
python asset_indexer.py index android "Pixel-7" "/sdcard" --device "ABC123"

# 4. Index Google Drive (requires credentials.json from Google Cloud Console)
python asset_indexer.py index gdrive "MyDrive" "credentials.json"

# 5. Show overview across all locations
python asset_indexer.py stats

# 6. Find duplicate files > 10MB
python asset_indexer.py duplicates --min-size 10

# 7. Export statistics
python asset_indexer.py export backup_stats.json
```
