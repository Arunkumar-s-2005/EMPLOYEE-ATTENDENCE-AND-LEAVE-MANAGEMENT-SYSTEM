import sqlite3
from flask import Flask, request, render_template, redirect, url_for, session, flash
from datetime import datetime, date
import hashlib

app = Flask(__name__)
app.secret_key = 'your-secret-key'  # Replace with a secure key in production

def init_db():
    conn = sqlite3.connect('attendance.db')
    conn.execute('PRAGMA foreign_keys = ON')
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'employee'
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            date TEXT NOT NULL,
            status TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS leaves (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            leave_type TEXT NOT NULL,
            start_date TEXT NOT NULL,
            end_date TEXT NOT NULL,
            reason TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    hashed_password = hashlib.sha256('admin'.encode()).hexdigest()
    cursor.execute('INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)',
                   ('admin', hashed_password, 'admin'))
    cursor.execute('INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)',
                   ('employee1', hashed_password, 'employee'))
    
    conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect('attendance.db')
    conn.row_factory = sqlite3.Row
    return conn

with app.app_context():
    init_db()

@app.route('/')
def index():
    if 'user_id' in session:
        if session['role'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', 
                          (username, password)).fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    
    if request.method == 'POST':
        if 'mark_attendance' in request.form:
            today = date.today().isoformat()
            conn.execute('INSERT INTO attendance (user_id, date, status) VALUES (?, ?, ?)',
                        (session['user_id'], today, 'present'))
            conn.commit()
            flash('Attendance marked successfully')
        
        elif 'leave_type' in request.form:
            leave_type = request.form['leave_type']
            start_date = request.form['start_date']
            end_date = request.form['end_date']
            reason = request.form['reason']
            
            conn.execute('INSERT INTO leaves (user_id, leave_type, start_date, end_date, reason, status) VALUES (?, ?, ?, ?, ?, ?)',
                        (session['user_id'], leave_type, start_date, end_date, reason, 'pending'))
            conn.commit()
            flash('Leave request submitted')
    
    attendance = conn.execute('SELECT * FROM attendance WHERE user_id = ? ORDER BY date DESC',
                            (session['user_id'],)).fetchall()
    leaves = conn.execute('SELECT * FROM leaves WHERE user_id = ? ORDER BY start_date DESC',
                         (session['user_id'],)).fetchall()
    conn.close()
    
    return render_template('dashboard.html', attendance=attendance, leaves=leaves)

@app.route('/admin', methods=['GET', 'POST'])
def admin_dashboard():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    
    if request.method == 'POST':
        if 'new_username' in request.form:
            username = request.form['new_username']
            password = hashlib.sha256(request.form['new_password'].encode()).hexdigest()
            
            existing_user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            if existing_user:
                flash('Username already exists')
            else:
                conn.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                            (username, password, 'employee'))
                conn.commit()
                flash('Employee added successfully')
        
        elif 'leave_id' in request.form:
            leave_id = request.form['leave_id']
            action = request.form['action']
            status = 'approved' if action == 'approve' else 'rejected'
            
            conn.execute('UPDATE leaves SET status = ? WHERE id = ?', (status, leave_id))
            conn.commit()
            flash(f'Leave request {status}')
    
    leaves = conn.execute('SELECT l.*, u.username FROM leaves l JOIN users u ON l.user_id = u.id ORDER BY l.start_date DESC').fetchall()
    attendance = conn.execute('SELECT a.*, u.username FROM attendance a JOIN users u ON a.user_id = u.id ORDER BY a.date DESC').fetchall()
    conn.close()
    
    return render_template('admin.html', leaves=leaves, attendance=attendance)

if __name__ == '__main__':
    app.run(debug=True)