import sqlite3
import pandas as pd
from flask import send_file, Flask, render_template, request, redirect, url_for, g, session, flash
import os
from decimal import Decimal
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta


app = Flask(__name__, static_folder='static')
app.secret_key = 'your_secret_key_here'  # Replace with a secure secret key in production

# Set session lifetime to 30 minutes
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)

DATABASE = 'expenses.db'

@app.before_request
def clear_session_on_start_or_if_not_logged_in():
    """Clear the session on app start or if no user is logged in."""
    if not session.get('user_id'):
        session.clear()

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # Enable column name access
    return db

def init_db():
    with app.app_context():
        db = get_db()
        
        # Check schema for all tables
        tables_to_check = ['users', 'expenses', 'categories', 'budgets']
        existing_tables = {row['name'] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        
        # Handle users table
        if 'users' not in existing_tables:
            db.execute('''CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    email TEXT,
                    role TEXT NOT NULL DEFAULT 'viewer' CHECK (role IN ('treasurer', 'auditor', 'viewer')))''')
        else:
            # Check if columns exist
            cols = {col['name'] for col in db.execute("PRAGMA table_info(users)").fetchall()}
            if 'email' not in cols:
                db.execute("ALTER TABLE users ADD COLUMN email TEXT")
            if 'role' not in cols:
                db.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'viewer' CHECK (role IN ('treasurer', 'auditor', 'viewer'))")
        
        # Handle expenses table
        if 'expenses' not in existing_tables:
            db.execute('''CREATE TABLE expenses (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        date TEXT NOT NULL,
                        description TEXT NOT NULL,
                        amount REAL NOT NULL,
                        category TEXT NOT NULL,
                        receipt_number TEXT,
                        user_id INTEGER,
                        FOREIGN KEY (user_id) REFERENCES users (id))''')
        else:
            # Check if user_id column exists
            cols = {col['name'] for col in db.execute("PRAGMA table_info(expenses)").fetchall()}
            if 'user_id' not in cols:
                db.execute("ALTER TABLE expenses ADD COLUMN user_id INTEGER")
        
        # Handle categories table
        if 'categories' not in existing_tables:
            db.execute('''CREATE TABLE categories (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        user_id INTEGER,
                        FOREIGN KEY (user_id) REFERENCES users (id))''')
        else:
            # Check if user_id column exists
            cols = {col['name'] for col in db.execute("PRAGMA table_info(categories)").fetchall()}
            if 'user_id' not in cols:
                db.execute("ALTER TABLE categories ADD COLUMN user_id INTEGER")
        
        # Handle budgets table
        if 'budgets' not in existing_tables:
            db.execute('''CREATE TABLE budgets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        category TEXT NOT NULL,
                        amount REAL NOT NULL,
                        user_id INTEGER,
                        FOREIGN KEY (user_id) REFERENCES users (id))''')
        else:
            # Check if user_id column exists
            cols = {col['name'] for col in db.execute("PRAGMA table_info(budgets)").fetchall()}
            if 'user_id' not in cols:
                db.execute("ALTER TABLE budgets ADD COLUMN user_id INTEGER")
            
            # Check if the table has a primary key column
            if 'id' not in cols:
                # For budgets, recreate the table with proper structure
                # First, back up the data
                budget_data = db.execute("SELECT category, amount, user_id FROM budgets").fetchall()
                
                # Drop and recreate table
                db.execute("DROP TABLE budgets")
                db.execute('''CREATE TABLE budgets (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            category TEXT NOT NULL,
                            amount REAL NOT NULL,
                            user_id INTEGER,
                            FOREIGN KEY (user_id) REFERENCES users (id))''')
                
                # Restore data
                for budget in budget_data:
                    db.execute("INSERT INTO budgets (category, amount, user_id) VALUES (?, ?, ?)",
                              (budget['category'], budget['amount'], budget['user_id']))
        
        # Commit all changes
        db.commit()

def role_required(roles):
    def decorator(view):
        def wrapped_view(**kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            
            db = get_db()
            user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
            
            if user['role'] not in roles:
                flash("You don't have permission to access this page.")
                return redirect(url_for('home'))
            
            return view(**kwargs)
        wrapped_view.__name__ = view.__name__
        return wrapped_view
    return decorator

init_db()

# Authentication routes
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
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        password_confirm = request.form['password_confirm']
        # Fixed: Use proper form.get() with only one default value
        role = request.form.get('x', 'viewer')  # Default to 'viewer' if not provided
        
        # Validate input
        if not username or not password or not email:
            flash('All fields are required')
            return render_template('register.html')
            
        if password != password_confirm:
            flash('Passwords do not match')
            return render_template('register.html')
        
        # Validate role is one of the allowed values
        if role not in ('treasurer', 'auditor', 'viewer'):
            flash('Invalid role selected')
            return render_template('register.html')
        
        db = get_db()
        
        # Check if username already exists
        user_exists = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if user_exists:
            flash('Username already exists')
            return render_template('register.html')
        
        # Check if email column exists before querying it
        email_column = db.execute("PRAGMA table_info(users)").fetchall()
        email_exists = any(column['name'] == 'email' for column in email_column)
        
        if email_exists:
            # Only check for email existence if the column exists
            email_used = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            if email_used:
                flash('Email already registered')
                return render_template('register.html')
        
        # Create new user with all required fields
        hashed_password = generate_password_hash(password)
        
        # Get all columns in the users table
        columns = [column['name'] for column in db.execute("PRAGMA table_info(users)").fetchall()]
        
        # Include role in the INSERT statement
        if 'role' in columns:
            if 'email' in columns:
                db.execute('INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)',
                        (username, hashed_password, email, role))
            else:
                db.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                        (username, hashed_password, role))
        else:
            if 'email' in columns:
                db.execute('INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
                        (username, hashed_password, email))
            else:
                db.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                        (username, hashed_password))
        
        db.commit()
        
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Login required decorator
def login_required(view):
    def wrapped_view(**kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return view(**kwargs)
    wrapped_view.__name__ = view.__name__
    return wrapped_view

@app.route('/')
@login_required
def home():
    db = get_db()
    user_id = session['user_id']
    cursor = db.execute('SELECT * FROM categories WHERE user_id = ? ORDER BY name', (user_id,))
    categories = cursor.fetchall()
    
    # Add default categories for new users if they don't exist
    default_categories = ['Snacks', 'Meals', 'Transportation', 'Materials']
    existing_categories = [category['name'] for category in categories]
    
    for category in default_categories:
        if category not in existing_categories:
            db.execute('INSERT INTO categories (name, user_id) VALUES (?, ?)', 
                      (category, user_id))
    
    db.commit()
    
    # Refresh categories after adding defaults
    cursor = db.execute('SELECT * FROM categories WHERE user_id = ? ORDER BY name', (user_id,))
    categories = cursor.fetchall()
    
    return render_template('home.html', categories=categories, username=session.get('username'))

@app.route('/add_category', methods=['POST'])
@login_required
def add_category():
    new_category = request.form['new_category']
    user_id = session['user_id']
    
    if new_category:
        db = get_db()
        db.execute('INSERT INTO categories (name, user_id) VALUES (?, ?)', 
                   (new_category, user_id))
        db.commit()
    return redirect(url_for('home'))

@app.route('/add_funding/<category>', methods=['POST'])
@login_required
def add_funding(category):
    funding_amount = float(request.form['funding_amount'])
    user_id = session['user_id']
    db = get_db()

    # Check if budget exists for this category
    cursor = db.execute("SELECT amount FROM budgets WHERE category = ? AND user_id = ?", 
                       (category, user_id))
    row = cursor.fetchone()

    if row:
        # Update existing budget
        db.execute("UPDATE budgets SET amount = amount + ? WHERE category = ? AND user_id = ?", 
                  (funding_amount, category, user_id))
    else:
        # Create new budget record
        db.execute("INSERT INTO budgets (category, amount, user_id) VALUES (?, ?, ?)", 
                  (category, funding_amount, user_id))

    db.commit()
    return redirect(url_for('category_page', category=category))

@app.route('/delete_category/<int:category_id>', methods=['POST'])
@login_required
def delete_category(category_id):
    user_id = session['user_id']
    db = get_db()
    
    # Check if category belongs to user
    category = db.execute('SELECT * FROM categories WHERE id = ? AND user_id = ?', 
                         (category_id, user_id)).fetchone()
    
    if category:
        db.execute('DELETE FROM categories WHERE id = ?', (category_id,))
        db.commit()
    
    return redirect(url_for('home'))

@app.route('/export_to_csv/<category>', methods=['GET'])
@login_required
def export_to_csv(category):
    user_id = session['user_id']
    conn = sqlite3.connect(DATABASE)
    query = "SELECT date, description, amount, category, receipt_number FROM expenses WHERE category = ? AND user_id = ?"
    try:
        df = pd.read_sql_query(query, conn, params=(category, user_id))
        if df.empty:
            return f"No data found for category: {category}"
        csv_file = f'{category}_expenses.csv'
        df.to_csv(csv_file, index=False)
    except Exception as e:
        return f"Error in exporting data: {str(e)}"
    finally:
        conn.close()
    
    return send_file(csv_file, as_attachment=True) if os.path.exists(csv_file) else "Error in exporting CSV file"

@app.route('/category/<category>')
@login_required
def category_page(category):
    user_id = session['user_id']
    db = get_db()

    try:
        # Fetch expenses for this user and category, ordering by date descending (newest first)
        cursor = db.execute("""
            SELECT id, date, description, amount, category, receipt_number 
            FROM expenses 
            WHERE LOWER(category) = LOWER(?) AND user_id = ?
            ORDER BY date DESC
        """, (category, user_id))
        
        expenses = cursor.fetchall()
        total_expense = sum(row['amount'] for row in expenses)

        # Fetch the budget for this category and user
        cursor = db.execute("""
            SELECT amount FROM budgets 
            WHERE category = ? AND user_id = ?
        """, (category, user_id))
        
        budget_row = cursor.fetchone()
        remaining_budget = budget_row['amount'] if budget_row else 0.00

        return render_template(
            'category.html',
            category=category,
            expenses=expenses,
            total_expense=total_expense,
            remaining_budget=remaining_budget,
            username=session.get('username')
        )

    except Exception as e:
        print("Error:", str(e))
        return f"Error loading category page: {str(e)}"

@app.route('/add_expense/<category>', methods=['POST'])
@login_required
def add_expense(category):
    # Get form data for the expense
    date = request.form['date']
    description = request.form['description']
    amount = float(request.form['amount'])
    receipt_number = request.form.get('receipt_number', '')  # Optional field
    user_id = session['user_id']
    
    db = get_db()
    
    # Check if there's enough budget for this expense
    cursor = db.execute("SELECT amount FROM budgets WHERE category = ? AND user_id = ?", 
                       (category, user_id))
    budget_row = cursor.fetchone()
    
    # If no budget exists yet
    if not budget_row:
        flash(f'No budget allocated for {category}. Please add funding first.', 'error')
        return redirect(url_for('category_page', category=category))
    
    # If budget exists but is insufficient
    if budget_row['amount'] < amount:
        available = budget_row['amount']
        needed = amount
        shortage = needed - available
        flash(f'Insufficient budget! Available: ₱{available:.2f}, Needed: ₱{needed:.2f}, Shortage: ₱{shortage:.2f}', 'error')
        return redirect(url_for('category_page', category=category))
    
    # Add the expense to the expenses table
    db.execute("""
        INSERT INTO expenses (date, description, amount, category, receipt_number, user_id) 
        VALUES (?, ?, ?, ?, ?, ?)
    """, (date, description, amount, category, receipt_number, user_id))
    
    # Reduce the budget amount
    db.execute("""
        UPDATE budgets SET amount = amount - ? WHERE category = ? AND user_id = ?
    """, (amount, category, user_id))
    
    db.commit()
    flash('Expense added successfully!', 'success')
    return redirect(url_for('category_page', category=category))

@app.route('/remove_expense/<int:expense_id>/<category>', methods=['POST'])
@login_required
def remove_expense(expense_id, category):
    user_id = session['user_id']
    db = get_db()

    # Debugging: Print the expense ID, category, and user ID
    print(f"Expense ID: {expense_id}, Category: {category}, User ID: {user_id}")

    # Retrieve the expense amount before deleting
    cursor = db.execute("SELECT amount FROM expenses WHERE id = ? AND user_id = ?", 
                       (expense_id, user_id))
    expense = cursor.fetchone()

    if expense:
        expense_amount = expense['amount']

        # Delete the expense
        db.execute("DELETE FROM expenses WHERE id = ? AND user_id = ?", 
                  (expense_id, user_id))

        # Add back the expense amount to the budget
        cursor = db.execute("SELECT amount FROM budgets WHERE category = ? AND user_id = ?", 
                           (category, user_id))
        budget_row = cursor.fetchone()

        if budget_row:
            new_budget = budget_row['amount'] + expense_amount
            db.execute("UPDATE budgets SET amount = ? WHERE category = ? AND user_id = ?", 
                      (new_budget, category, user_id))

    db.commit()
    flash('Expense removed successfully!', 'success')
    return redirect(url_for('category_page', category=category))

@app.route('/minus_funding/<category>', methods=['POST'])
@login_required
def minus_funding(category):
    funding_amount = float(request.form['funding_amount'])
    user_id = session['user_id']
    db = get_db()

    # Check if budget exists for this category
    cursor = db.execute("SELECT amount FROM budgets WHERE category = ? AND user_id = ?", 
                       (category, user_id))
    row = cursor.fetchone()

    if row:
        # Subtract funding from the existing budget
        new_budget = row['amount'] - funding_amount
        if new_budget < 0:
            flash('Cannot subtract more than the current budget.', 'error')
        else:
            db.execute("UPDATE budgets SET amount = ? WHERE category = ? AND user_id = ?", 
                      (new_budget, category, user_id))
            flash(f'₱{funding_amount:.2f} subtracted from the budget for {category}.', 'success')
    else:
        flash(f'No budget exists for {category}.', 'error')

    db.commit()
    return redirect(url_for('category_page', category=category))

@app.teardown_appcontext
def close_db(error):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

if __name__ == '__main__':
    app.run(debug=True)