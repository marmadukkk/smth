import sqlite3
import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import csv

app = Flask(__name__)
app.secret_key = 'secret_key'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS ads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        category_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        image_path TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (category_id) REFERENCES categories (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ad_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        text TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (ad_id) REFERENCES ads (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        message TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        read BOOLEAN DEFAULT FALSE,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS bans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        reason TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS likes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ad_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        UNIQUE(ad_id, user_id),
        FOREIGN KEY (ad_id) REFERENCES ads (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    cursor.execute("SELECT COUNT(*) FROM categories")
    if cursor.fetchone()[0] == 0:
        cursor.executemany("INSERT INTO categories (name) VALUES (?)", [
            ('Buy/Sell',),
            ('Events',),
            ('Lost/Found',),
            ('Housing',),
            ('Jobs',)
        ])
    cursor.execute("SELECT COUNT(*) FROM admins")
    if cursor.fetchone()[0] == 0:
        hashed_pw = generate_password_hash('password')
        cursor.execute("INSERT INTO admins (username, password) VALUES (?, ?)", ('admin', hashed_pw))
    conn.commit()
    conn.close()

init_db()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def is_banned(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM bans WHERE user_id = ?", (user_id,))
    ban = cursor.fetchone()
    conn.close()
    return ban is not None

@app.route('/')
def index():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM categories")
    categories = cursor.fetchall()
    conn.close()
    theme = session.get('theme', 'light')
    return render_template('index.html', categories=categories, theme=theme)

@app.route('/toggle_theme')
def toggle_theme():
    theme = 'dark' if session.get('theme', 'light') == 'light' else 'light'
    session['theme'] = theme
    return redirect(request.referrer or url_for('index'))

@app.route('/category/<int:category_id>')
def category(category_id):
    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT ads.*, users.username FROM ads JOIN users ON ads.user_id = users.id WHERE category_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?", (category_id, per_page, offset))
    ads = cursor.fetchall()
    cursor.execute("SELECT COUNT(*) FROM ads WHERE category_id = ?", (category_id,))
    total = cursor.fetchone()[0]
    cursor.execute("SELECT name FROM categories WHERE id = ?", (category_id,))
    category_name = cursor.fetchone()[0]
    conn.close()
    pages = (total // per_page) + (1 if total % per_page else 0)
    theme = session.get('theme', 'light')
    return render_template('category.html', ads=ads, category_name=category_name, page=page, pages=pages, theme=theme)

@app.route('/ad/<int:ad_id>', methods=['GET', 'POST'])
def ad_detail(ad_id):
    if request.method == 'POST':
        if 'user_id' not in session:
            flash('Please log in to comment.')
            return redirect(url_for('login'))
        if is_banned(session['user_id']):
            flash('You are banned.')
            return redirect(url_for('index'))
        text = request.form['text']
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO comments (ad_id, user_id, text) VALUES (?, ?, ?)", (ad_id, session['user_id'], text))
        conn.commit()
        cursor.execute("SELECT user_id FROM ads WHERE id = ?", (ad_id,))
        ad_owner = cursor.fetchone()[0]
        if ad_owner != session['user_id']:
            cursor.execute("INSERT INTO notifications (user_id, message) VALUES (?, ?)", (ad_owner, f'New comment on your ad: {ad_id}'))
            conn.commit()
        conn.close()
        return redirect(url_for('ad_detail', ad_id=ad_id))
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT ads.*, users.username FROM ads JOIN users ON ads.user_id = users.id WHERE ads.id = ?", (ad_id,))
    ad = cursor.fetchone()
    cursor.execute("SELECT comments.*, users.username FROM comments JOIN users ON comments.user_id = users.id WHERE ad_id = ? ORDER BY created_at DESC", (ad_id,))
    comments = cursor.fetchall()
    cursor.execute("SELECT COUNT(*) FROM likes WHERE ad_id = ?", (ad_id,))
    likes = cursor.fetchone()[0]
    liked = False
    if 'user_id' in session:
        cursor.execute("SELECT * FROM likes WHERE ad_id = ? AND user_id = ?", (ad_id, session['user_id']))
        liked = cursor.fetchone() is not None
    conn.close()
    theme = session.get('theme', 'light')
    return render_template('ad_detail.html', ad=ad, comments=comments, likes=likes, liked=liked, theme=theme)

@app.route('/like/<int:ad_id>')
@login_required
def like(ad_id):
    if is_banned(session['user_id']):
        flash('You are banned.')
        return redirect(url_for('index'))
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO likes (ad_id, user_id) VALUES (?, ?)", (ad_id, session['user_id']))
        conn.commit()
    except sqlite3.IntegrityError:
        pass  # Already liked
    conn.close()
    return redirect(url_for('ad_detail', ad_id=ad_id))

@app.route('/add_ad', methods=['GET', 'POST'])
@login_required
def add_ad():
    if is_banned(session['user_id']):
        flash('You are banned.')
        return redirect(url_for('index'))
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        category_id = request.form['category_id']
        image_path = None
        if 'image' in request.files:
            file = request.files['image']
            if file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                image_path = filename
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO ads (title, description, category_id, user_id, image_path) VALUES (?, ?, ?, ?, ?)", (title, description, category_id, session['user_id'], image_path))
        conn.commit()
        conn.close()
        return redirect(url_for('index'))
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM categories")
    categories = cursor.fetchall()
    conn.close()
    theme = session.get('theme', 'light')
    return render_template('add_ad.html', categories=categories, theme=theme)

@app.route('/edit_ad/<int:ad_id>', methods=['GET', 'POST'])
@login_required
def edit_ad(ad_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ads WHERE id = ?", (ad_id,))
    ad = cursor.fetchone()
    if ad[4] != session['user_id']:  # user_id
        flash('You can only edit your own ads.')
        conn.close()
        return redirect(url_for('index'))
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        category_id = request.form['category_id']
        image_path = ad[5]  # Keep existing if no new
        if 'image' in request.files:
            file = request.files['image']
            if file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                image_path = filename
        cursor.execute("UPDATE ads SET title = ?, description = ?, category_id = ?, image_path = ? WHERE id = ?", (title, description, category_id, image_path, ad_id))
        conn.commit()
        conn.close()
        return redirect(url_for('ad_detail', ad_id=ad_id))
    cursor.execute("SELECT * FROM categories")
    categories = cursor.fetchall()
    conn.close()
    theme = session.get('theme', 'light')
    return render_template('edit_ad.html', ad=ad, categories=categories, theme=theme)

@app.route('/delete_ad/<int:ad_id>')
@login_required
def delete_ad(ad_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ads WHERE id = ?", (ad_id,))
    ad = cursor.fetchone()
    if ad[4] != session['user_id']:  # user_id
        flash('You can only delete your own ads.')
        conn.close()
        return redirect(url_for('index'))
    cursor.execute("DELETE FROM ads WHERE id = ?", (ad_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == 'POST':
        query = request.form['query']
        category_id = request.form.get('category_id')
        date_from = request.form.get('date_from')
        date_to = request.form.get('date_to')
        sql = "SELECT ads.*, users.username FROM ads JOIN users ON ads.user_id = users.id WHERE (title LIKE ? OR description LIKE ?)"
        params = [f'%{query}%', f'%{query}%']
        if category_id:
            sql += " AND category_id = ?"
            params.append(category_id)
        if date_from:
            sql += " AND created_at >= ?"
            params.append(date_from)
        if date_to:
            sql += " AND created_at <= ?"
            params.append(date_to)
        sql += " ORDER BY created_at DESC"
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute(sql, params)
        ads = cursor.fetchall()
        cursor.execute("SELECT * FROM categories")
        categories = cursor.fetchall()
        conn.close()
        theme = session.get('theme', 'light')
        return render_template('search.html', ads=ads, query=query, categories=categories, theme=theme)
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM categories")
    categories = cursor.fetchall()
    conn.close()
    theme = session.get('theme', 'light')
    return render_template('search.html', categories=categories, theme=theme)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        email = request.form['email']
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", (username, password, email))
            conn.commit()
            flash('Registration successful. Please log in.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists.')
        conn.close()
    theme = session.get('theme', 'light')
    return render_template('register.html', theme=theme)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            return redirect(url_for('index'))
        flash('Invalid username or password.')
    theme = session.get('theme', 'light')
    return render_template('login.html', theme=theme)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/notifications')
@login_required
def notifications():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC", (session['user_id'],))
    notifs = cursor.fetchall()
    cursor.execute("UPDATE notifications SET read = TRUE WHERE user_id = ?", (session['user_id'],))
    conn.commit()
    conn.close()
    theme = session.get('theme', 'light')
    return render_template('notifications.html', notifs=notifs, theme=theme)

@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM admins WHERE username = ?", (username,))
        admin = cursor.fetchone()
        conn.close()
        if admin and check_password_hash(admin[2], password):
            session['admin'] = True
            return redirect(url_for('admin_panel'))
        flash('Invalid admin credentials.')
    theme = session.get('theme', 'light')
    return render_template('admin_login.html', theme=theme)

@app.route('/admin/panel')
@admin_required
def admin_panel():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT ads.id, ads.title, ads.description, categories.name, users.username FROM ads JOIN categories ON ads.category_id = categories.id JOIN users ON ads.user_id = users.id")
    ads = cursor.fetchall()
    cursor.execute("SELECT users.id, users.username, users.email, bans.id AS ban_id FROM users LEFT JOIN bans ON users.id = bans.user_id")
    users = cursor.fetchall()
    cursor.execute("SELECT categories.name, COUNT(ads.id) FROM categories LEFT JOIN ads ON categories.id = ads.category_id GROUP BY categories.id")
    stats = cursor.fetchall()
    conn.close()
    theme = session.get('theme', 'light')
    return render_template('admin_panel.html', ads=ads, users=users, stats=stats, theme=theme)

@app.route('/admin/edit_ad/<int:ad_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_ad(ad_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ads WHERE id = ?", (ad_id,))
    ad = cursor.fetchone()
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        category_id = request.form['category_id']
        image_path = ad[5]
        if 'image' in request.files:
            file = request.files['image']
            if file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                image_path = filename
        cursor.execute("UPDATE ads SET title = ?, description = ?, category_id = ?, image_path = ? WHERE id = ?", (title, description, category_id, image_path, ad_id))
        conn.commit()
        conn.close()
        return redirect(url_for('admin_panel'))
    cursor.execute("SELECT * FROM categories")
    categories = cursor.fetchall()
    conn.close()
    theme = session.get('theme', 'light')
    return render_template('admin_edit_ad.html', ad=ad, categories=categories, theme=theme)

@app.route('/admin/delete/<int:ad_id>')
@admin_required
def admin_delete(ad_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM ads WHERE id = ?", (ad_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('admin_panel'))

@app.route('/admin/ban/<int:user_id>')
@admin_required
def admin_ban(user_id):
    reason = request.args.get('reason', 'No reason provided')
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO bans (user_id, reason) VALUES (?, ?)", (user_id, reason))
    conn.commit()
    conn.close()
    return redirect(url_for('admin_panel'))

@app.route('/admin/unban/<int:user_id>')
@admin_required
def admin_unban(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM bans WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('admin_panel'))

@app.route('/admin/export_csv')
@admin_required
def admin_export_csv():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ads")
    ads = cursor.fetchall()
    conn.close()
    with open('ads.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['ID', 'Title', 'Description', 'Category ID', 'User ID', 'Image Path', 'Created At'])
        writer.writerows(ads)
    return send_from_directory('.', 'ads.csv', as_attachment=True)

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)