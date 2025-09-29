# pentoolkit/utils/database.py
import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import timedelta # Ensure you have this package installed

class PentoolkitDatabase:
    def __init__(self, db_path: str = "./pentoolkit_scans.db"):
        self.db_path = Path(db_path)
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database with all required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Scans table - main scan tracking
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                modules TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'running',
                start_time TEXT NOT NULL,
                end_time TEXT,
                results_path TEXT,
                notes TEXT,
                config_snapshot TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Scan results table - detailed module results
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                module TEXT NOT NULL,
                result_data TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'success',
                error_message TEXT,
                execution_time REAL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
            )
        ''')
        
        # Targets table - track target information
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT UNIQUE NOT NULL,
                ip_address TEXT,
                last_scanned TEXT,
                scan_count INTEGER DEFAULT 0,
                notes TEXT,
                tags TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Vulnerabilities table - track findings
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                target TEXT NOT NULL,
                module TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                recommendation TEXT,
                cvss_score REAL,
                cve_id TEXT,
                port INTEGER,
                service TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
            )
        ''')
        
        # Configuration snapshots
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS config_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                config_hash TEXT UNIQUE,
                config_data TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create indexes for better performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_start_time ON scans(start_time)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_results_scan_id ON scan_results(scan_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_targets_hostname ON targets(hostname)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_id ON vulnerabilities(scan_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_vulnerabilities_target ON vulnerabilities(target)')
        
        conn.commit()
        conn.close()
    
    def log_scan_start(self, target: str, modules: str, config_snapshot: Dict = None) -> int:
        """Log scan start and return scan ID"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        config_json = json.dumps(config_snapshot) if config_snapshot else None
        
        cursor.execute('''
            INSERT INTO scans (target, modules, status, start_time, config_snapshot)
            VALUES (?, ?, ?, ?, ?)
        ''', (target, modules, 'running', datetime.utcnow().isoformat(), config_json))
        
        scan_id = cursor.lastrowid
        
        # Update or create target entry
        self._update_target(cursor, target)
        
        conn.commit()
        conn.close()
        return scan_id
    
    def log_scan_complete(self, scan_id: int, status: str = 'completed', results_path: str = None):
        """Mark scan as complete"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE scans 
            SET status = ?, end_time = ?, results_path = ?
            WHERE id = ?
        ''', (status, datetime.utcnow().isoformat(), results_path, scan_id))
        
        conn.commit()
        conn.close()
    
    def log_module_result(self, scan_id: int, module: str, result_data: Dict, 
                         status: str = 'success', error_message: str = None, 
                         execution_time: float = None):
        """Log individual module results"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO scan_results (scan_id, module, result_data, status, error_message, execution_time)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (scan_id, module, json.dumps(result_data), status, error_message, execution_time))
        
        conn.commit()
        conn.close()
    
    def log_vulnerability(self, scan_id: int, target: str, module: str, severity: str,
                         title: str, description: str = None, recommendation: str = None,
                         cvss_score: float = None, cve_id: str = None, 
                         port: int = None, service: str = None):
        """Log a vulnerability finding"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO vulnerabilities 
            (scan_id, target, module, severity, title, description, recommendation, 
             cvss_score, cve_id, port, service)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (scan_id, target, module, severity, title, description, recommendation,
              cvss_score, cve_id, port, service))
        
        conn.commit()
        conn.close()
    
    def get_scan_history(self, target: str = None, days: int = 30) -> List[Dict]:
        """Get scan history with optional filtering"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = """
            SELECT id, target, modules, status, start_time, end_time, results_path
            FROM scans 
            WHERE start_time > ?
        """
        params = [(datetime.utcnow() - timedelta(days=days)).isoformat()]
        
        if target:
            query += " AND target LIKE ?"
            params.append(f"%{target}%")
        
        query += " ORDER BY start_time DESC"
        
        cursor.execute(query, params)
        results = cursor.fetchall()
        conn.close()
        
        return [
            {
                'id': row[0], 'target': row[1], 'modules': row[2],
                'status': row[3], 'start_time': row[4], 'end_time': row[5],
                'results_path': row[6]
            }
            for row in results
        ]
    
    def get_scan_details(self, scan_id: int) -> Optional[Dict]:
        """Get detailed information about a specific scan"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT target, modules, status, start_time, end_time, results_path, notes, config_snapshot
            FROM scans WHERE id = ?
        """, (scan_id,))
        
        result = cursor.fetchone()
        if not result:
            conn.close()
            return None
        
        # Get module results
        cursor.execute("""
            SELECT module, result_data, status, error_message, execution_time
            FROM scan_results WHERE scan_id = ?
        """, (scan_id,))
        
        module_results = [
            {
                'module': row[0], 'result_data': json.loads(row[1]) if row[1] else {},
                'status': row[2], 'error_message': row[3], 'execution_time': row[4]
            }
            for row in cursor.fetchall()
        ]
        
        # Get vulnerabilities
        cursor.execute("""
            SELECT module, severity, title, description, port, service
            FROM vulnerabilities WHERE scan_id = ?
        """, (scan_id,))
        
        vulnerabilities = [
            {
                'module': row[0], 'severity': row[1], 'title': row[2],
                'description': row[3], 'port': row[4], 'service': row[5]
            }
            for row in cursor.fetchall()
        ]
        
        conn.close()
        
        return {
            'scan_id': scan_id,
            'target': result[0],
            'modules': result[1],
            'status': result[2],
            'start_time': result[3],
            'end_time': result[4],
            'results_path': result[5],
            'notes': result[6],
            'config_snapshot': json.loads(result[7]) if result[7] else {},
            'module_results': module_results,
            'vulnerabilities': vulnerabilities
        }
    
    def search_scans(self, query: str, days: int = 30) -> List[Dict]:
        """Search scans by target name, modules, etc."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, target, modules, status, start_time
            FROM scans 
            WHERE (target LIKE ? OR modules LIKE ? OR notes LIKE ?)
            AND start_time > ?
            ORDER BY start_time DESC
        """, (f"%{query}%", f"%{query}%", f"%{query}%", 
              (datetime.utcnow() - timedelta(days=days)).isoformat()))
        
        results = cursor.fetchall()
        conn.close()
        
        return [
            {
                'id': row[0], 'target': row[1], 'modules': row[2],
                'status': row[3], 'start_time': row[4]
            }
            for row in results
        ]
    
    def get_statistics(self) -> Dict:
        """Get comprehensive database statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Basic counts
        cursor.execute("SELECT COUNT(*) FROM scans")
        total_scans = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM scans WHERE status = 'completed'")
        completed_scans = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM scans WHERE status = 'running'")
        running_scans = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM targets")
        total_targets = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        total_vulnerabilities = cursor.fetchone()[0]
        
        # Top targets
        cursor.execute("""
            SELECT target, COUNT(*) as count 
            FROM scans 
            GROUP BY target 
            ORDER BY count DESC 
            LIMIT 5
        """)
        top_targets = cursor.fetchall()
        
        # Vulnerability breakdown
        cursor.execute("""
            SELECT severity, COUNT(*) as count
            FROM vulnerabilities
            GROUP BY severity
        """)
        vuln_breakdown = dict(cursor.fetchall())
        
        # Module usage
        cursor.execute("""
            SELECT module, COUNT(*) as count
            FROM scan_results
            GROUP BY module
            ORDER BY count DESC
        """)
        module_usage = cursor.fetchall()
        
        conn.close()
        
        return {
            'total_scans': total_scans,
            'completed_scans': completed_scans,
            'running_scans': running_scans,
            'failed_scans': total_scans - completed_scans - running_scans,
            'total_targets': total_targets,
            'total_vulnerabilities': total_vulnerabilities,
            'vulnerability_breakdown': vuln_breakdown,
            'top_targets': top_targets,
            'module_usage': module_usage
        }
    
    def cleanup_old_data(self, days: int = 30) -> int:
        """Remove old scan data"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
        cursor.execute("DELETE FROM scans WHERE start_time < ?", (cutoff,))
        removed = cursor.rowcount
        
        conn.commit()
        conn.close()
        return removed
    
    def _update_target(self, cursor, target: str):
        """Update target information"""
        cursor.execute("""
            INSERT OR REPLACE INTO targets (hostname, last_scanned, scan_count)
            VALUES (?, ?, COALESCE((SELECT scan_count FROM targets WHERE hostname = ?), 0) + 1)
        """, (target, datetime.utcnow().isoformat(), target))

# Global database instance
db = PentoolkitDatabase()

def get_database() -> PentoolkitDatabase:
    """Get the global database instance"""
    return db