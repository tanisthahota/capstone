import sqlite3

conn = sqlite3.connect('users.db')
c = conn.cursor()

c.execute('DROP TABLE IF EXISTS users')
c.execute('CREATE TABLE users (username TEXT, password TEXT)')
c.execute("INSERT INTO users (username, password) VALUES ('admin', 'admin123')")
c.execute("INSERT INTO users (username, password) VALUES ('user', 'user123')")

conn.commit()
conn.close()
