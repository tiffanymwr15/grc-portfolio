"""
GRC Framework - Risk Register Integration
==========================================
Integration with the SQLite risk register from Lesson 13.

Demonstrates:
  - Database abstraction
  - Query building
  - Data transformation
"""

import sqlite3
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime

from ..config import get_config


@dataclass
class Risk:
    """Risk data class."""
    risk_id: str
    title: str
    description: str
    severity: str
    status: str
    category: str
    score: int
    owner: str
    created_at: str


class RiskRegister:
    """
    Interface to the risk register database.
    
    Provides clean API for risk operations without
    exposing database details to callers.
    """
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or get_config().risk_db_path
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def get_open_risks(self, min_score: int = 0) -> List[Risk]:
        """Get all open risks above a score threshold."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT risk_id, title, description, 
                   CASE 
                       WHEN score >= 30 THEN 'CRITICAL'
                       WHEN score >= 22 THEN 'HIGH'
                       WHEN score >= 12 THEN 'MEDIUM'
                       ELSE 'LOW'
                   END as severity,
                   status, risk_category as category, score, owner, created_at
            FROM ai_risks
            WHERE status IN ('IDENTIFIED', 'ASSESSING', 'MITIGATING')
              AND score >= ?
            ORDER BY score DESC
        """, (min_score,))
        
        risks = []
        for row in cursor.fetchall():
            risks.append(Risk(**dict(row)))
        
        conn.close()
        return risks
    
    def get_summary(self) -> Dict[str, Any]:
        """Get risk summary statistics."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Total counts
        cursor.execute("SELECT status, COUNT(*) FROM ai_risks GROUP BY status")
        by_status = dict(cursor.fetchall())
        
        # Critical count
        cursor.execute("""
            SELECT COUNT(*) FROM ai_risks 
            WHERE score >= 30 AND status IN ('IDENTIFIED', 'ASSESSING', 'MITIGATING')
        """)
        critical = cursor.fetchone()[0]
        
        # By category
        cursor.execute("SELECT risk_category, COUNT(*) FROM ai_risks GROUP BY risk_category")
        by_category = dict(cursor.fetchall())
        
        conn.close()
        
        open_count = (
            by_status.get('IDENTIFIED', 0) + 
            by_status.get('ASSESSING', 0) + 
            by_status.get('MITIGATING', 0)
        )
        
        return {
            "total": sum(by_status.values()),
            "open": open_count,
            "critical": critical,
            "by_category": by_category,
            "by_status": by_status
        }
    
    def add_risk(self, title: str, description: str, likelihood: int, 
                 impact: int, category: str, owner: str = "GRC Team") -> str:
        """Add a new risk to the register."""
        risk_id = f"RISK-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        score = likelihood * impact  # Simple calculation
        
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Check if ai_risks table exists (from ai_risk_register.py)
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='ai_risks'
        """)
        
        if cursor.fetchone():
            cursor.execute("""
                INSERT INTO ai_risks 
                (risk_id, title, description, ai_system_type, ai_phase, risk_category,
                 likelihood, impact, score, owner, status, created_at, updated_at)
                VALUES (?, ?, ?, 'Other', 'Production', ?, ?, ?, ?, ?, 'IDENTIFIED', datetime('now'), datetime('now'))
            """, (risk_id, title, description, category, likelihood, impact, score, owner))
            conn.commit()
        
        conn.close()
        return risk_id
