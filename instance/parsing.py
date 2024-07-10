import sqlite3

# Connect to the database
conn = sqlite3.connect('users.db')

# Create a cursor object
cursor = conn.cursor()

# Get a list of all tables in the database
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cursor.fetchall()

# Print each table's contents
for table in tables:
    print(f"Table: {table[0]}")
    cursor.execute(f"SELECT * FROM {table[0]}")
    rows = cursor.fetchall()
    for row in rows:
        print(row)
    print()  # Print a blank line between tables for clarity

# Close connection
conn.close()
