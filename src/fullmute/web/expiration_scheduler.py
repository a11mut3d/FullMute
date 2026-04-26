from datetime import datetime
from fullmute.web.database import get_db_connection
from fullmute.utils.logger import setup_logger

logger = setup_logger()


def cleanup_expired_users():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        now = datetime.now().isoformat()
        
        
        cursor.execute("""
            SELECT id, username, expires_at, grace_period_ends
            FROM users
            WHERE grace_period_ends IS NOT NULL
            AND grace_period_ends < ?
            AND expired_at IS NULL
        """, (now,))
        
        expired_users = cursor.fetchall()
        
        for user in expired_users:
            user_id = user['id']
            username = user['username']
            grace_period_ends = user['grace_period_ends']
            
            
            cursor.execute("""
                UPDATE users SET expired_at = ? WHERE id = ?
            """, (now, user_id))
            
            logger.info(f"User {username} (ID: {user_id}) grace period ended ({grace_period_ends}), marked for deletion")
        
        
        
        cursor.execute("""
            DELETE FROM users
            WHERE expired_at IS NOT NULL
            AND grace_period_ends < datetime(?, '-3 days')
        """, (now,))
        
        deleted_count = cursor.rowcount
        
        if deleted_count > 0:
            logger.info(f"Deleted {deleted_count} users whose grace period + 3 days ended")
        
        conn.commit()
        
        return {
            'marked_expired': len(expired_users),
            'deleted': deleted_count
        }


def check_expiring_soon():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, username, expires_at, role
            FROM users
            WHERE expires_at IS NOT NULL
            AND expires_at > datetime('now')
            AND expires_at < datetime('now', '+7 days')
        """)
        
        expiring_soon = cursor.fetchall()
        
        return [dict(user) for user in expiring_soon]
