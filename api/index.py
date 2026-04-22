import sqlite3
import pandas as pd
from flask import send_file, Flask, render_template, request, redirect, url_for, g, session, flash
import os
from decimal import Decimal
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta

# Initialize Flask with paths set to look outside the 'api' folder
app = Flask(__name__, 
            template_folder='../templates', 
            static_folder='../static')

app.secret_key = 'your_secret_key_here'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)

# VERCEL FIX: Use /tmp folder for SQLite
DATABASE = '/tmp/expenses.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

def init_db():
    with app.app_context():
        db = get_db()
        db.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    email TEXT,
                    role TEXT NOT NULL DEFAULT 'viewer')''')
        
        db.execute('''CREATE TABLE IF NOT EXISTS expenses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date TEXT NOT NULL,
                    description TEXT NOT NULL,
                    amount REAL NOT NULL,
                    category TEXT NOT NULL,
                    receipt_number TEXT,
                    user_id INTEGER,
                    FOREIGN KEY (user_id) REFERENCES users (id))''')

        db.execute('''CREATE TABLE IF NOT EXISTS categories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    user_id INTEGER,
                    FOREIGN KEY (user_id) REFERENCES users (id))''')

        db.execute('''CREATE TABLE IF NOT EXISTS budgets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    category TEXT NOT NULL,
                    amount REAL NOT NULL,
                    user_id INTEGER,
                    FOREIGN KEY (user_id) REFERENCES users (id))''')
        db.commit()

init_db()

# --- Helpers & Decorators ---

def login_required(view):
    def wrapped_view(**kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return view(**kwargs)
    wrapped_view.__name__ = view.__name__
    return wrapped_view

@app.before_request
def clear_session_on_start():
    if not session.get('user_id'):
        session.clear()

# --- Routes ---

@app.route('/')
@login_required
def home():
    db = get_db()
    user_id = session['user_id']
    cursor = db.execute('SELECT * FROM categories WHERE user_id = ? ORDER BY name', (user_id,))
    categories = cursor.fetchall()
    
    default_categories = ['Snacks', 'Meals', 'Transportation', 'Materials']
    existing_categories = [category['name'] for category in categories]
    
    for category in default_categories:
        if category not in existing_categories:
            db.execute('INSERT INTO categories (name, user_id) VALUES (?, ?)', (category, user_id))
    db.commit()
    
    cursor = db.execute('SELECT * FROM categories WHERE user_id = ? ORDER BY name', (user_id,))
    categories = cursor.fetchall()
    return render_template('home.html', categories=categories, username=session.get('username'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if user and check_password_hash(user['password'], password):
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('home'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        password_confirm = request.form['password_confirm']
        role = request.form.get('role', 'viewer')
        
        if password != password_confirm:
            flash('Passwords do not match')
            return render_template('register.html')
        
        db = get_db()
        hashed_password = generate_password_hash(password)
        try:
            db.execute('INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)',
                       (username, hashed_password, email, role))
            db.commit()
            flash('Registration successful. Please log in.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists')
    return render_template('register.html')

@app.route('/category/<category>')
@login_required
def category_page(category):
    user_id = session['user_id']
    db = get_db()
    expenses = db.execute("SELECT * FROM expenses WHERE LOWER(category) = LOWER(?) AND user_id = ? ORDER BY date DESC", (category, user_id)).fetchall()
    total_expense = sum(row['amount'] for row in expenses)
    budget_row = db.execute("SELECT amount FROM budgets WHERE category = ? AND user_id = ?", (category, user_id)).fetchone()
    remaining_budget = budget_row['amount'] if budget_row else 0.00
    return render_template('category.html', category=category, expenses=expenses, total_expense=total_expense, remaining_budget=remaining_budget, username=session.get('username'))

@app.route('/add_expense/<category>', methods=['POST'])
@login_required
def add_expense(category):
    date, description, amount = request.form['date'], request.form['description'], float(request.form['amount'])
    receipt = request.form.get('receipt_number', '')
    user_id = session['user_id']
    db = get_db()
    
    budget_row = db.execute("SELECT amount FROM budgets WHERE category = ? AND user_id = ?", (category, user_id)).fetchone()
    if not budget_row or budget_row['amount'] < amount:
        flash('Insufficient budget!', 'error')
    else:
        db.execute("INSERT INTO expenses (date, description, amount, category, receipt_number, user_id) VALUES (?, ?, ?, ?, ?, ?)", (date, description, amount, category, receipt, user_id))
        db.execute("UPDATE budgets SET amount = amount - ? WHERE category = ? AND user_id = ?", (amount, category, user_id))
        db.commit()
        flash('Expense added!', 'success')
    return redirect(url_for('category_page', category=category))

@app.route('/add_funding/<category>', methods=['POST'])
@login_required
def add_funding(category):
    amount = float(request.form['funding_amount'])
    user_id = session['user_id']
    db = get_db()
    row = db.execute("SELECT amount FROM budgets WHERE category = ? AND user_id = ?", (category, user_id)).fetchone()
    if row:
        db.execute("UPDATE budgets SET amount = amount + ? WHERE category = ? AND user_id = ?", (amount, category, user_id))
    else:
        db.execute("INSERT INTO budgets (category, amount, user_id) VALUES (?, ?, ?)", (category, amount, user_id))
    db.commit()
    return redirect(url_for('category_page', category=category))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.teardown_appcontext
def close_db(error):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# For Vercel
app.debug = True
