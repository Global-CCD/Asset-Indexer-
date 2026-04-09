#!/usr/bin/env python3
"""
Asset Indexer - Universal File Catalog with Cryptographic Deduplication
Supports Local Storage, Cloud Drives (Google Drive, OneDrive, Backblaze), and Android
"""

import os
import sys
import sqlite3
import hashlib
import json
import argparse
from pathlib import Path
from datetime import datetime
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Iterator, Tuple
from contextlib import contextmanager
import logging

# Optional dependencies with graceful degradation
try:
    import blake3
    HAS_BLAKE3 = True
except ImportError:
    HAS_BLAKE3 = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False


# Configuration
@dataclass
class IndexConfig:
    db_path: str = "asset_index.db"
    hash_algorithm: str = "blake3"  # or "sha256"
    chunk_size: int = 8192  # 8KB chunks for hashing
    quick_scan: bool = False  # Skip hashing, just metadata
    
    # Cloud credentials (load from env or config file)
    google_drive_token: Optional[str] = None
    onedrive_token: Optional[str] = None
    backblaze_key_id: Optional[str] = None
    backblaze_app_key: Optional[str] = None


class HashCalculator:
    """Cryptographic hash calculation with algorithm flexibility"""
    
    def __init__(self, algorithm: str = "blake3"):
        self.algorithm = algorithm.lower()
        if self.algorithm == "blake3" and not HAS_BLAKE3:
            logging.warning("BLAKE3 not installed, falling back to SHA-256")
            self.algorithm = "sha256"
    
    def new_hasher(self):
        if self.algorithm == "blake3":
            return blake3.blake3()
        return hashlib.sha256()
    
    def hash_file(self, filepath: Path) -> Optional[str]:
        """Calculate hash of file, returns hex digest"""
        hasher = self.new_hasher()
        try:
            with open(filepath, 'rb') as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except (IOError, OSError) as e:
            logging.error(f"Error hashing {filepath}: {e}")
            return None


@dataclass
class FileEntry:
    """Universal file representation"""
    path: str
    name: str
    size_bytes: int
    modified_time: float
    location_type: str  # local, google_drive, onedrive, backblaze, android
    location_name: str  # device/drive identifier
    hash_value: Optional[str] = None
    hash_type: Optional[str] = None
    last_indexed: Optional[str] = None
    
    def to_dict(self):
        return asdict(self)


class DatabaseManager:
    """SQLite backend for asset persistence"""
    
    SCHEMA = """
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        path TEXT NOT NULL,
        name TEXT NOT NULL,
        size_bytes INTEGER NOT NULL,
        modified_time REAL NOT NULL,
        location_type TEXT NOT NULL,
        location_name TEXT NOT NULL,
        hash_value TEXT,
        hash_type TEXT,
        last_indexed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(path, location_type, location_name)
    );
    
    CREATE INDEX IF NOT EXISTS idx_hash ON files(hash_value);
    CREATE INDEX IF NOT EXISTS idx_location ON files(location_type, location_name);
    CREATE INDEX IF NOT EXISTS idx_size ON files(size_bytes);
    """
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.init_db()
    
    @contextmanager
    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def init_db(self):
        with self.get_connection() as conn:
            conn.executescript(self.SCHEMA)
            # Enable WAL mode for better concurrency
            conn.execute("PRAGMA journal_mode=WAL")
    
    def upsert_file(self, entry: FileEntry):
        """Insert or update file entry"""
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO files 
                (path, name, size_bytes, modified_time, location_type, location_name, 
                 hash_value, hash_type, last_indexed)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(path, location_type, location_name) DO UPDATE SET
                size_bytes=excluded.size_bytes,
                modified_time=excluded.modified_time,
                hash_value=excluded.hash_value,
                hash_type=excluded.hash_type,
                last_indexed=CURRENT_TIMESTAMP
            """, (
                entry.path, entry.name, entry.size_bytes, entry.modified_time,
                entry.location_type, entry.location_name, entry.hash_value,
                entry.hash_type, datetime.now().isoformat()
            ))
    
    def batch_upsert(self, entries: List[FileEntry]):
        """Batch insert for performance"""
        with self.get_connection() as conn:
            data = [(
                e.path, e.name, e.size_bytes, e.modified_time,
                e.location_type, e.location_name, e.hash_value,
                e.hash_type, datetime.now().isoformat()
            ) for e in entries]
            conn.executemany("""
                INSERT INTO files 
                (path, name, size_bytes, modified_time, location_type, location_name, 
                 hash_value, hash_type, last_indexed)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(path, location_type, location_name) DO UPDATE SET
                size_bytes=excluded.size_bytes,
                modified_time=excluded.modified_time,
                hash_value=excluded.hash_value,
                hash_type=excluded.hash_type,
                last_indexed=CURRENT_TIMESTAMP
            """, data)
    
    def get_stats(self) -> Dict:
        """Get overview statistics"""
        with self.get_connection() as conn:
            # Overall stats
            total = conn.execute(
                "SELECT COUNT(*) as count, COALESCE(SUM(size_bytes), 0) as total_size FROM files"
            ).fetchone()
            
            # Per location breakdown
            locations = conn.execute("""
                SELECT location_type, location_name, 
                       COUNT(*) as file_count, 
                       COALESCE(SUM(size_bytes), 0) as total_size
                FROM files
                GROUP BY location_type, location_name
                ORDER BY total_size DESC
            """).fetchall()
            
            # Hash coverage
            hash_stats = conn.execute("""
                SELECT hash_type, COUNT(*) as count 
                FROM files 
                WHERE hash_value IS NOT NULL
                GROUP BY hash_type
            """).fetchall()
            
            return {
                'total_files': total['count'],
                'total_bytes': total['total_size'],
                'locations': [dict(row) for row in locations],
                'hash_coverage': {row['hash_type']: row['count'] for row in hash_stats}
            }
    
    def find_duplicates(self, min_size: int = 0) -> List[Dict]:
        """Find files with identical hashes"""
        with self.get_connection() as conn:
            query = """
                SELECT hash_value, hash_type, COUNT(*) as dup_count, 
                       GROUP_CONCAT(path || '@' || location_name, ' | ') as locations,
                       SUM(size_bytes) as wasted_space
                FROM files
                WHERE hash_value IS NOT NULL 
                AND size_bytes >= ?
                GROUP BY hash_value
                HAVING COUNT(*) > 1
                ORDER BY wasted_space DESC
            """
            return [dict(row) for row in conn.execute(query, (min_size,)).fetchall()]
    
    def clear_location(self, location_type: str, location_name: str):
        """Clear index for specific location (before re-indexing)"""
        with self.get_connection() as conn:
            conn.execute(
                "DELETE FROM files WHERE location_type=? AND location_name=?", 
                (location_type, location_name)
            )


class StorageAdapter(ABC):
    """Abstract base for storage backends"""
    
    def __init__(self, location_name: str, config: IndexConfig):
        self.location_name = location_name
        self.config = config
    
    @abstractmethod
    def scan(self) -> Iterator[FileEntry]:
        """Yield FileEntry objects"""
        pass
    
    @abstractmethod
    def test_connection(self) -> bool:
        """Verify access to storage"""
        pass


class LocalFSAdapter(StorageAdapter):
    """Local filesystem adapter (macOS, Linux, Windows, Android via ADB)"""
    
    def __init__(self, location_name: str, root_path: str, config: IndexConfig):
        super().__init__(location_name, config)
        self.root = Path(root_path).resolve()
        self.hash_calc = HashCalculator(config.hash_algorithm)
    
    def test_connection(self) -> bool:
        return self.root.exists() and self.root.is_dir()
    
    def scan(self) -> Iterator[FileEntry]:
        hash_calc = self.hash_calc
        quick = self.config.quick_scan
        
        for filepath in self.root.rglob("*"):
            if not filepath.is_file():
                continue
            
            stat = filepath.stat()
            entry = FileEntry(
                path=str(filepath.relative_to(self.root)),
                name=filepath.name,
                size_bytes=stat.st_size,
                modified_time=stat.st_mtime,
                location_type="local",
                location_name=self.location_name,
                hash_type=self.config.hash_algorithm if not quick else None
            )
            
            if not quick:
                entry.hash_value = hash_calc.hash_file(filepath)
            
            yield entry


class AndroidADBAdapter(StorageAdapter):
    """Android device via ADB (Android Debug Bridge)"""
    
    def __init__(self, location_name: str, device_id: Optional[str], config: IndexConfig):
        super().__init__(location_name, config)
        self.device_id = device_id
        self.hash_calc = HashCalculator(config.hash_algorithm)
    
    def test_connection(self) -> bool:
        import subprocess
        try:
            cmd = ["adb", "devices"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            return self.device_id in result.stdout or "device" in result.stdout
        except FileNotFoundError:
            return False
    
    def scan(self) -> Iterator[FileEntry]:
        """Scan Android storage via ADB shell find command"""
        import subprocess
        import tempfile
        
        # Export file list via ADB
        cmd = ["adb", "-s", self.device_id] if self.device_id else ["adb"]
        cmd.extend(["shell", "find", "/sdcard", "-type", "f", "-printf", "%s %T@ %p\\n"])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            for line in result.stdout.splitlines():
                parts = line.split(maxsplit=2)
                if len(parts) != 3:
                    continue
                
                size, mtime, path = parts
                entry = FileEntry(
                    path=path,
                    name=Path(path).name,
                    size_bytes=int(size),
                    modified_time=float(mtime),
                    location_type="android",
                    location_name=self.location_name,
                    hash_type=None  # ADB doesn't support easy hashing
                )
                yield entry
        except Exception as e:
            logging.error(f"ADB scan failed: {e}")


class GoogleDriveAdapter(StorageAdapter):
    """Google Drive adapter (requires API setup)"""
    
    def __init__(self, location_name: str, credentials_path: str, config: IndexConfig):
        super().__init__(location_name, config)
        self.credentials = credentials_path
        self.service = None
    
    def test_connection(self) -> bool:
        try:
            from googleapiclient.discovery import build
            from google.oauth2.credentials import Credentials
            creds = Credentials.from_authorized_user_file(self.credentials)
            self.service = build('drive', 'v3', credentials=creds)
            self.service.files().get(fileId="root").execute()
            return True
        except Exception as e:
            logging.error(f"Google Drive connection failed: {e}")
            return False
    
    def scan(self) -> Iterator[FileEntry]:
        """Scan Google Drive files"""
        if not self.service:
            self.test_connection()
        
        page_token = None
        while True:
            results = self.service.files().list(
                pageSize=1000,
                fields="nextPageToken, files(id, name, size, modifiedTime, md5Checksum)",
                pageToken=page_token
            ).execute()
            
            for file in results.get('files', []):
                if 'size' not in file:  # Skip folders
                    continue
                
                # Google provides MD5, convert or store separately
                entry = FileEntry(
                    path=file['id'],
                    name=file['name'],
                    size_bytes=int(file.get('size', 0)),
                    modified_time=datetime.fromisoformat(file['modifiedTime'].replace('Z', '+00:00')).timestamp(),
                    location_type="google_drive",
                    location_name=self.location_name,
                    hash_value=file.get('md5Checksum'),
                    hash_type="md5"  # Note: GDrive uses MD5, not BLAKE3/SHA256
                )
                yield entry
            
            page_token = results.get('nextPageToken')
            if not page_token:
                break


class AssetIndexer:
    """Main indexing orchestrator"""
    
    def __init__(self, config: IndexConfig):
        self.config = config
        self.db = DatabaseManager(config.db_path)
        self.console = Console() if RICH_AVAILABLE else None
    
    def index_location(self, adapter: StorageAdapter, batch_size: int = 100):
        """Index a storage location with progress tracking"""
        if not adapter.test_connection():
            raise ConnectionError(f"Cannot connect to {adapter.location_name}")
        
        # Clear existing entries for this location
        self.db.clear_location(adapter.location_type, adapter.location_name)
        
        batch = []
        count = 0
        
        iterator = adapter.scan()
        if TQDM_AVAILABLE and not self.console:
            iterator = tqdm(iterator, desc=f"Indexing {adapter.location_name}")
        
        for entry in iterator:
            batch.append(entry)
            count += 1
            
            if len(batch) >= batch_size:
                self.db.batch_upsert(batch)
                batch = []
        
        if batch:
            self.db.batch_upsert(batch)
        
        return count
    
    def show_overview(self):
        """Display statistics overview"""
        stats = self.db.get_stats()
        
        if self.console:
            self._rich_overview(stats)
        else:
            self._text_overview(stats)
    
    def _rich_overview(self, stats: Dict):
        """Rich formatted output"""
        self.console.print(f"\n[bold cyan]Asset Index Overview[/bold cyan]")
        self.console.print(f"Total Files: {stats['total_files']:,}")
        self.console.print(f"Total Size: {self._human_readable_size(stats['total_bytes'])}\n")
        
        table = Table(title="Storage Locations")
        table.add_column("Type", style="cyan")
        table.add_column("Name", style="magenta")
        table.add_column("Files", justify="right")
        table.add_column("Size", justify="right")
        
        for loc in stats['locations']:
            table.add_row(
                loc['location_type'],
                loc['location_name'],
                f"{loc['file_count']:,}",
                self._human_readable_size(loc['total_size'])
            )
        self.console.print(table)
        
        if stats['hash_coverage']:
            self.console.print(f"\n[green]Hash Coverage:[/green]")
            for hash_type, count in stats['hash_coverage'].items():
                self.console.print(f"  {hash_type}: {count:,} files")
    
    def _text_overview(self, stats: Dict):
        """Plain text output"""
        print(f"\n=== Asset Index Overview ===")
        print(f"Total Files: {stats['total_files']:,}")
        print(f"Total Size: {self._human_readable_size(stats['total_bytes'])}")
        print("\nStorage Locations:")
        print(f"{'Type':<15} {'Name':<20} {'Files':<10} {'Size':<15}")
        print("-" * 60)
        for loc in stats['locations']:
            print(f"{loc['location_type']:<15} {loc['location_name']:<20} "
                  f"{loc['file_count']:<10,} {self._human_readable_size(loc['total_size']):<15}")
    
    def find_duplicates(self, min_size_mb: float = 0):
        """Find and display duplicate files"""
        min_bytes = min_size_mb * 1024 * 1024
        dups = self.db.find_duplicates(min_bytes)
        
        if not dups:
            print("No duplicates found.")
            return
        
        total_wasted = sum(d['wasted_space'] for d in dups)
        
        if self.console:
            table = Table(title=f"Duplicate Files (Total Wasted: {self._human_readable_size(total_wasted)})")
            table.add_column("Hash", style="cyan")
            table.add_column("Count", justify="right")
            table.add_column("Wasted Space", justify="right")
            table.add_column("Locations")
            
            for dup in dups[:50]:  # Limit to top 50
                table.add_row(
                    dup['hash_value'][:16] + "...",
                    str(dup['dup_count']),
                    self._human_readable_size(dup['wasted_space']),
                    dup['locations'][:100]
                )
            self.console.print(table)
        else:
            print(f"\n=== Duplicate Files (Total Wasted: {self._human_readable_size(total_wasted)}) ===")
            for dup in dups:
                print(f"\nHash: {dup['hash_value']} ({dup['dup_count']} copies)")
                print(f"Wasted: {self._human_readable_size(dup['wasted_space'])}")
                for loc in dup['locations'].split(' | ')[:5]:
                    print(f"  - {loc}")
    
    def export_json(self, output_path: str):
        """Export database to JSON"""
        stats = self.db.get_stats()
        with open(output_path, 'w') as f:
            json.dump(stats, f, indent=2)
        print(f"Exported overview to {output_path}")
    
    @staticmethod
    def _human_readable_size(size_bytes: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"


def main():
    parser = argparse.ArgumentParser(description="Asset Indexer - Universal File Catalog")
    parser.add_argument("--db", default="asset_index.db", help="Database path")
    parser.add_argument("--hash", choices=["blake3", "sha256"], default="blake3", 
                       help="Hash algorithm (default: blake3)")
    parser.add_argument("--quick", action="store_true", 
                       help="Quick scan (skip hashing)")
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Index command
    index_parser = subparsers.add_parser("index", help="Index a location")
    index_parser.add_argument("type", choices=["local", "android", "gdrive", "onedrive", "backblaze"])
    index_parser.add_argument("name", help="Name for this location")
    index_parser.add_argument("path", help="Root path or credentials")
    index_parser.add_argument("--device", help="Android device ID (for android type)")
    
    # Stats command
    subparsers.add_parser("stats", help="Show overview statistics")
    
    # Duplicates command
    dup_parser = subparsers.add_parser("duplicates", help="Find duplicate files")
    dup_parser.add_argument("--min-size", type=float, default=0, help="Minimum file size in MB")
    
    # Export command
    export_parser = subparsers.add_parser("export", help="Export to JSON")
    export_parser.add_argument("output", help="Output JSON file")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    config = IndexConfig(
        db_path=args.db,
        hash_algorithm=args.hash,
        quick_scan=args.quick
    )
    
    indexer = AssetIndexer(config)
    
    if args.command == "index":
        adapter = None
        if args.type == "local":
            adapter = LocalFSAdapter(args.name, args.path, config)
        elif args.type == "android":
            adapter = AndroidADBAdapter(args.name, args.device, config)
        elif args.type == "gdrive":
            adapter = GoogleDriveAdapter(args.name, args.path, config)
        else:
            print(f"Adapter for {args.type} not yet implemented")
            return
        
        try:
            count = indexer.index_location(adapter)
            print(f"Indexed {count} files from {args.name}")
        except Exception as e:
            print(f"Indexing failed: {e}")
            raise
    
    elif args.command == "stats":
        indexer.show_overview()
    
    elif args.command == "duplicates":
        indexer.find_duplicates(args.min_size)
    
    elif args.command == "export":
        indexer.export_json(args.output)


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    main()
