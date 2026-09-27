import sqlite3
from datetime import datetime, timedelta

conn = sqlite3.connect("datadharma.db")
cursor = conn.cursor()

expired_time = datetime.now() - timedelta(minutes=1)

cursor.execute("""
    UPDATE access_requests
    SET expires_at = ?
    WHERE id = 2
""", (expired_time.isoformat(),))

conn.commit()
conn.close()

print("TEST EXPIRY TIME SET")
print("Expired at:", expired_time.strftime("%Y-%m-%d %H:%M:%S"))
