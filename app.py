from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import bcrypt
from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# Setup Flask app and secret key
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

# Load encryption key for passwords
key = os.getenv("ENCRYPTION_KEY").encode()
fernet = Fernet(key)

# DB Setup
def init_db():
    conn = sqlite3.connect('vault.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT UNIQUE,
                    password TEXT
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS vault (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER,
                    website TEXT,
                    login TEXT,
                    password BLOB
                )''')
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def home():
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        print(f"Registering username: {username}")  # 🔍 Debug line
        password = bcrypt.hashpw(request.form['password'].encode(), bcrypt.gensalt())

        try:
            conn = sqlite3.connect('vault.db')
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
        except sqlite3.IntegrityError:
            return "Username already exists!"
        finally:
            conn.close()
        print("Redirecting to /login")  # 🔍 Debug
        return redirect('/login') # ✅ Important: Always return a response
    return render_template('register.html') # ✅ For GET requests

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password_input = request.form['password'].encode()  # user input in bytes

        conn = sqlite3.connect('vault.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user and bcrypt.checkpw(password_input, user[2]):  # ✅ fix here
            session['user_id'] = user[0]
            return redirect('/dashboard')
        else:
            return "Login failed. Try again."

    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')

    conn = sqlite3.connect('vault.db')
    c = conn.cursor()

    # Handle new password save
    if request.method == 'POST':
        website = request.form['website']
        login = request.form['login']
        password_plain = request.form['password'].encode()
        enc_password = fernet.encrypt(password_plain)

        c.execute("INSERT INTO vault (user_id, website, login, password) VALUES (?, ?, ?, ?)",
                  (session['user_id'], website, login, enc_password))
        conn.commit()

    # 🔍 Search logic
    search_term = request.args.get('search')
    if search_term:
        like_query = f"%{search_term}%"
        c.execute("SELECT id, website, login, password FROM vault WHERE user_id = ?  AND (website LIKE ? OR login LIKE ?)",
                  (session['user_id'], like_query, like_query))
    else:
        c.execute("SELECT id, website, login, password FROM vault WHERE user_id = ?",
                  (session['user_id'],))
        
    entries = c.fetchall()
    conn.close()

    # Decrypt passwords
    decrypted_entries = []
    for entry in entries:
        decrypted_password = fernet.decrypt(entry[3]).decode()
        decrypted_entries.append((entry[0], entry[1], entry[2], decrypted_password))

    return render_template('dashboard.html', entries=decrypted_entries)

# Delete button under Dashboard
@app.route('/delete/<int:id>', methods=['POST'])
def delete(id):
    if 'user_id' not in session:
        return redirect('/login')

    conn = sqlite3.connect('vault.db')
    c = conn.cursor()
    c.execute("DELETE FROM vault WHERE id = ? AND user_id = ?", (id, session['user_id']))
    conn.commit()
    conn.close()
    return redirect('/dashboard')

# Adding Edit Button
@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit(id):
    if 'user_id' not in session:
        return redirect('/login')

    conn = sqlite3.connect('vault.db')
    c = conn.cursor()

    if request.method == 'POST':
        website = request.form['website']
        login = request.form['login']
        password_plain = request.form['password'].encode()
        enc_password = fernet.encrypt(password_plain)
        c.execute("""
            UPDATE vault SET website = ?, login = ?, password = ? 
            WHERE id = ? AND user_id = ?
        """, (website, login, enc_password, id, session['user_id']))
        conn.commit()
        conn.close()
        return redirect('/dashboard')

    # GET request – load current entry
    c.execute("SELECT * FROM vault WHERE id = ? AND user_id = ?", (id, session['user_id']))
    entry = c.fetchone()
    conn.close()
    return render_template('edit.html', entry=entry)



@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

# ✅ Test route to debug register.html
@app.route('/test-register')
def test_register():
    print("Rendering register.html")  # Debug line
    return render_template('register.html')


if __name__ == '__main__':
    app.run(debug=True)
