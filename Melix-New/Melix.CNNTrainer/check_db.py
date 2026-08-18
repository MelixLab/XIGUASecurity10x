import sqlite3
import os

def check_db(path):
    print(f'Checking: {path}')
    if not os.path.exists(path):
        print('  Not found')
        return
    try:
        conn = sqlite3.connect(path)
        c = conn.cursor()
        c.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = c.fetchall()
        print(f'  Tables: {tables}')
        if tables:
            for t in tables:
                c.execute(f'SELECT COUNT(*) FROM {t[0]}')
                count = c.fetchone()[0]
                print(f'    {t[0]}: {count} rows')
        conn.close()
    except Exception as e:
        print(f'  Error: {e}')

check_db('blackData/Dataset.db')
check_db('WhiteData/Dataset0.db')
check_db('WhiteData/Dataset1.db')
