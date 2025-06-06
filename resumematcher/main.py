from flask import Flask, request, render_template, send_from_directory, redirect, url_for, session, flash
import os
import docx2txt
import PyPDF2
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import mysql.connector
import re
from datetime import datetime
from functools import wraps
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Set a strong secret key for session management
app.secret_key = 'your_secret_key_here'  # Changed from os.urandom(24) to be consistent across restarts

# Session configuration
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True if using HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

app.config['UPLOAD_FOLDER'] = 'uploads/'

# Allowed file extensions for uploads
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Database configuration
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'resumematcher_db'
}

def get_db_connection():
    try:
        connection = mysql.connector.connect(**db_config)
        return connection
    except mysql.connector.Error as err:
        print(f"Database connection failed: {err}")
        if err.errno == mysql.connector.errorcode.ER_BAD_DB_ERROR:
            # Database doesn't exist, create it
            connection = mysql.connector.connect(
                host='localhost',
                user='root',
                password=''
            )
            cursor = connection.cursor()
            cursor.execute("CREATE DATABASE IF NOT EXISTS resumematcher_db")
            
            # Create necessary tables
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    email VARCHAR(100) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    first_name VARCHAR(50),
                    last_name VARCHAR(50),
                    profile_picture VARCHAR(255),
                    phone VARCHAR(20),
                    linkedin_url VARCHAR(255),
                    github_url VARCHAR(255),
                    account_type ENUM('free', 'premium') DEFAULT 'free',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS admins (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    email VARCHAR(100) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    first_name VARCHAR(50),
                    last_name VARCHAR(50),
                    profile_picture VARCHAR(255),
                    role ENUM('super_admin', 'content_admin', 'support_admin') DEFAULT 'support_admin',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP NULL DEFAULT NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS resumes (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    title VARCHAR(100) NOT NULL,
                    file_path VARCHAR(255) NOT NULL,
                    ats_score INT DEFAULT 0,
                    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_analytics (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    resume_score INT DEFAULT 0,
                    job_matches INT DEFAULT 0,
                    applications INT DEFAULT 0,
                    profile_views INT DEFAULT 0,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)

            # Insert default admin if not exists
            cursor.execute("""
                INSERT IGNORE INTO admins (username, email, password)
                VALUES ('admin', 'admin@example.com', 'admin123')
            """)

            cursor.close()
            connection.commit()
            connection.close()
            
            # Try connecting again
            return mysql.connector.connect(**db_config)
        raise
    return None

# Create tables if they don't exist
def init_db():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Update admins table to include updated_at column
        cursor.execute('''
            ALTER TABLE admins
            ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP 
            DEFAULT CURRENT_TIMESTAMP 
            ON UPDATE CURRENT_TIMESTAMP
        ''')
        
        # Create admin_activity_log table if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admin_activity_log (
                id INT AUTO_INCREMENT PRIMARY KEY,
                admin_id INT NOT NULL,
                action VARCHAR(255) NOT NULL,
                details TEXT,
                ip_address VARCHAR(45),
                user_agent VARCHAR(255),
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE CASCADE
            )
        ''')
        
        conn.commit()
        print("Database tables updated successfully")
        
    except Exception as e:
        print(f"Error updating database tables: {str(e)}")
        if conn:
            conn.rollback()
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# Initialize database
init_db()

# Ensure the uploads directory exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Function to extract text from PDF
def extract_text_from_pdf(file_path):
    text = ""
    with open(file_path, 'rb') as file:
        reader = PyPDF2.PdfReader(file)
        for page in reader.pages:
            text += page.extract_text()
    return text

# Function to extract text from DOCX
def extract_text_from_docx(file_path):
    return docx2txt.process(file_path)

# Function to extract text from TXT
def extract_text_from_txt(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        return file.read()

# Function to extract text based on file type
def extract_text(file_path):
    if file_path.endswith('.pdf'):
        return extract_text_from_pdf(file_path)
    elif file_path.endswith('.docx'):
        return extract_text_from_docx(file_path)
    elif file_path.endswith('.txt'):
        return extract_text_from_txt(file_path)
    else:
        return ""

# Authentication helper functions
def is_valid_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None

def is_logged_in():
    return 'user_id' in session

def is_admin():
    return 'is_admin' in session and session['is_admin']

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_logged_in():
            flash('Please login first.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_admin():
            flash('Admin access required.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Authentication routes
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not all([username, email, password, confirm_password]):
            flash('All fields are required.')
            return redirect(url_for('signup'))

        if not is_valid_email(email):
            flash('Invalid email format.')
            return redirect(url_for('signup'))

        if password != confirm_password:
            flash('Passwords do not match.')
            return redirect(url_for('signup'))

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute('SELECT * FROM users WHERE username = %s OR email = %s', (username, email))
            if cursor.fetchone():
                flash('Username or email already exists.')
                return redirect(url_for('signup'))

            cursor.execute('INSERT INTO users (username, email, password) VALUES (%s, %s, %s)',
                         (username, email, password))
            conn.commit()
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except Exception as e:
            flash('An error occurred during registration.')
            return redirect(url_for('signup'))
        finally:
            cursor.close()
            conn.close()

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        is_admin_login = request.form.get('is_admin') == 'true'

        print(f"Login attempt - Username: {username}, Is Admin: {is_admin_login}")

        if not username or not password:
            flash('Please provide both username and password.')
            return redirect(url_for('login'))

        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            if not conn:
                flash('Unable to connect to database.')
                return redirect(url_for('login'))

            cursor = conn.cursor(dictionary=True)
            table = 'admins' if is_admin_login else 'users'
            
            # Query user
            cursor.execute(f"SELECT * FROM {table} WHERE username = %s", (username,))
            user = cursor.fetchone()
            
            if not user:
                flash('Invalid username or password.')
                return redirect(url_for('login'))
            
            # Verify password
            if user['password'] == password:
                try:
                    # Clear any existing session
                    session.clear()
                    
                    # Set session data
                    session['logged_in'] = True
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['email'] = user['email']
                    if is_admin_login:
                        session['is_admin'] = True
                        # Update last_login for admin
                        cursor.execute('''
                            UPDATE admins 
                            SET last_login = CURRENT_TIMESTAMP 
                            WHERE id = %s
                        ''', (user['id'],))
                        conn.commit()
                    
                    # Commit session
                    session.modified = True
                    
                    flash(f'Welcome back, {username}!')
                    return redirect(url_for('dashboard'))
                    
                except Exception as e:
                    print(f"Session error: {str(e)}")
                    flash('Error setting up session.')
                    return redirect(url_for('login'))
            else:
                flash('Invalid username or password.')
                return redirect(url_for('login'))

        except mysql.connector.Error as e:
            print(f"Database error: {str(e)}")
            flash('Database error occurred.')
            return redirect(url_for('login'))
        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Root route
@app.route('/')
def index():
    if not is_logged_in():
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

# Dashboard route (frameset)
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

# Protected routes
@app.route('/aichatbot')
@login_required
def aichatbot():
    return render_template('aichatbot.html')

@app.route('/resumeparser')
@login_required
def resumeparser():
    return render_template('resumeparser.html')

@app.route('/resumebuilder')
@login_required
def resumebuilder():
    return render_template('ResumeBuilder.html')

@app.route('/matchresume')
@login_required
def matchresume():
    return render_template('matchresume.html')

@app.route('/atschecker')
@login_required
def atschecker():
    return render_template('atschecker.html')

# Route to handle resume matching
@app.route('/matcher', methods=['GET', 'POST'])
def matcher():
    if request.method == 'POST':
        try:
            job_description = request.form.get('job_description')
            resume_files = request.files.getlist('resumes')  # Get multiple files

            print("Form Data Received:")  # Debug print
            print(f"Job Description: {bool(job_description)}")
            print(f"Number of Resumes: {len(resume_files)}")

            if not job_description or not resume_files:
                return render_template('matchresume.html', 
                                     message="Please upload resumes and enter a job description.")

            if len(resume_files) < 5:
                return render_template('matchresume.html',
                                     message="Please upload at least 5 resumes for comparison.")

            # Process each resume
            resumes_text = []
            filenames = []
            
            for resume_file in resume_files:
                if resume_file.filename == '':
                    continue
                    
                filename = os.path.join(app.config['UPLOAD_FOLDER'], resume_file.filename)
                resume_file.save(filename)
                resume_text = extract_text(filename)
                
                if resume_text.strip():  # Only add if we got some text
                    resumes_text.append(resume_text)
                    filenames.append(resume_file.filename)

            if not resumes_text:
                return render_template('matchresume.html',
                                     message="Could not extract text from any of the uploaded resumes.")

            # Vectorize job description and all resumes
            vectorizer = TfidfVectorizer(stop_words='english')
            all_documents = [job_description] + resumes_text
            vectors = vectorizer.fit_transform(all_documents)
            
            # Calculate similarities between job description and each resume
            job_vector = vectors[0:1]  # First document is job description
            resume_vectors = vectors[1:]  # Rest are resumes
            
            similarities = cosine_similarity(job_vector, resume_vectors)[0]
            
            # Create pairs of (filename, similarity) and sort by similarity
            resume_scores = list(zip(filenames, similarities))
            resume_scores.sort(key=lambda x: x[1], reverse=True)
            
            # Get top 5 resumes
            top_resumes = []
            similarity_scores = []
            
            for filename, score in resume_scores[:5]:
                top_resumes.append(filename)
                similarity_scores.append(round(score * 100, 2))

            print(f"Top Resumes: {top_resumes}")  # Debug print
            print(f"Scores: {similarity_scores}")  # Debug print

            return render_template('matchresume.html',
                                 message="Top matching resumes:",
                                 top_resumes=top_resumes,
                                 similarity_scores=similarity_scores)

        except Exception as e:
            print(f"Error processing request: {str(e)}")  # Debug print
            return render_template('matchresume.html',
                                 message=f"An error occurred while processing your request: {str(e)}")

    # For GET request or initial page load
    return render_template('matchresume.html')

# Route to handle resume analysis
@app.route('/analyze_resume', methods=['POST'])
def analyze_resume():
    if 'resume' not in request.files or 'job_description' not in request.form:
        return {'error': 'Missing resume or job description'}, 400

    resume_file = request.files['resume']
    job_description = request.form['job_description']

    if resume_file.filename == '':
        return {'error': 'No resume file selected'}, 400

    # Save and process the resume
    filename = os.path.join(app.config['UPLOAD_FOLDER'], resume_file.filename)
    resume_file.save(filename)
    resume_text = extract_text(filename)

    # Clean and process the texts
    resume_text = resume_text.lower()
    job_description = job_description.lower()

    # Create TF-IDF vectors
    vectorizer = TfidfVectorizer(stop_words='english')
    vectors = vectorizer.fit_transform([resume_text, job_description])
    similarity_score = cosine_similarity(vectors[0:1], vectors[1:2])[0][0] * 100

    # Extract important keywords from job description
    job_keywords = set([word for word, score in 
        zip(vectorizer.get_feature_names_out(), vectors[1].toarray()[0]) 
        if score > 0.1])

    # Extract keywords from resume
    resume_keywords = set([word for word, score in 
        zip(vectorizer.get_feature_names_out(), vectors[0].toarray()[0]) 
        if score > 0.1])

    # Find matching and missing keywords
    matched_keywords = list(job_keywords.intersection(resume_keywords))
    missing_keywords = list(job_keywords - resume_keywords)

    # Generate recommendations
    recommendations = []
    if similarity_score < 60:
        recommendations.append("Your resume needs significant improvement to match this job description.")
    if len(missing_keywords) > 0:
        recommendations.append(f"Consider adding these key terms to your resume: {', '.join(missing_keywords[:5])}")
    if similarity_score < 80:
        recommendations.append("Try to quantify your achievements with specific metrics and numbers.")
    if len(matched_keywords) < 10:
        recommendations.append("Include more industry-specific terminology from the job description.")

    return {
        'score': similarity_score,
        'matched_keywords': matched_keywords[:10],  # Limit to top 10 matches
        'missing_keywords': missing_keywords[:10],  # Limit to top 10 missing
        'recommendations': recommendations
    }

# Route to serve static files (CSS, JS, etc.)
@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

# Navigation route
@app.route('/navigation')
@login_required
def navigation():
    user_data = {
        'username': session.get('username'),
        'email': session.get('email'),
        'is_admin': session.get('is_admin', False)
    }
    return render_template('navigation.html', user=user_data)

# Welcome route (dashboard content)
@app.route('/welcome')
@login_required
def welcome():
    user_data = {
        'username': session.get('username'),
        'email': session.get('email'),
        'is_admin': session.get('is_admin', False),
        'account_type': 'premium'  # You can modify this based on your user data
    }

    # If user is admin, fetch admin stats
    if user_data['is_admin']:
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)

            # Get active users count
            cursor.execute("SELECT COUNT(*) as count FROM users WHERE last_login > DATE_SUB(NOW(), INTERVAL 30 DAY)")
            active_users = cursor.fetchone()['count']

            # Get resume uploads count
            cursor.execute("SELECT COUNT(*) as count FROM resumes")
            resume_uploads = cursor.fetchone()['count']

            # Get premium users count
            cursor.execute("SELECT COUNT(*) as count FROM users WHERE account_type = 'premium'")
            premium_users = cursor.fetchone()['count']

            # Calculate system load (example metric)
            system_load = 65  # This could be calculated based on your system metrics

            stats = {
                'active_users': active_users,
                'resume_uploads': resume_uploads,
                'premium_users': premium_users,
                'system_load': system_load
            }

            cursor.close()
            conn.close()

            return render_template('welcome.html', user=user_data, stats=stats)
        except Exception as e:
            print(f"Error fetching admin stats: {str(e)}")
            # Return empty stats if there's an error
            stats = {
                'active_users': 0,
                'resume_uploads': 0,
                'premium_users': 0,
                'system_load': 0
            }
            return render_template('welcome.html', user=user_data, stats=stats)
    else:
        # For regular users, fetch their stats
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)

            # Get user stats
            cursor.execute("""
                SELECT 
                    COALESCE(resume_score, 0) as resume_score,
                    COALESCE(job_matches, 0) as job_matches,
                    COALESCE(applications, 0) as applications,
                    COALESCE(profile_views, 0) as profile_views
                FROM user_analytics 
                WHERE user_id = %s
            """, (session.get('user_id'),))
            
            user_stats = cursor.fetchone()
            if not user_stats:
                user_stats = {
                    'resume_score': 0,
                    'job_matches': 0,
                    'applications': 0,
                    'profile_views': 0
                }

            cursor.close()
            conn.close()

            return render_template('welcome.html', user=user_data, user_stats=user_stats)
        except Exception as e:
            print(f"Error fetching user stats: {str(e)}")
            # Return empty stats if there's an error
            user_stats = {
                'resume_score': 0,
                'job_matches': 0,
                'applications': 0,
                'profile_views': 0
            }
            return render_template('welcome.html', user=user_data, user_stats=user_stats)

# Admin routes
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    # Check if the request is coming from within a frame
    if request.args.get('framed') != 'true':
        return redirect(url_for('dashboard'))
        
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Get total users count
        cursor.execute('SELECT COUNT(*) as count FROM users')
        total_users = cursor.fetchone()['count']
        
        # Get active resumes count
        cursor.execute('SELECT COUNT(*) as count FROM resumes')
        active_resumes = cursor.fetchone()['count']
        
        # Get total job applications
        cursor.execute('SELECT COUNT(*) as count FROM job_applications')
        total_applications = cursor.fetchone()['count']
        
        # Get premium users count
        cursor.execute('SELECT COUNT(*) as count FROM users WHERE account_type = "premium"')
        premium_users = cursor.fetchone()['count']
        
        # Get recent users
        cursor.execute('''
            SELECT id, username, email, account_type, created_at 
            FROM users 
            ORDER BY created_at DESC 
            LIMIT 5
        ''')
        recent_users = cursor.fetchall()
        
        # Get recent system logs
        cursor.execute('''
            SELECT created_at, log_type, message, source 
            FROM system_logs 
            ORDER BY created_at DESC 
            LIMIT 5
        ''')
        recent_logs = cursor.fetchall()
        
        # Get user registration trend (last 7 days)
        cursor.execute('''
            SELECT DATE(created_at) as date, COUNT(*) as count
            FROM users
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            GROUP BY DATE(created_at)
            ORDER BY date
        ''')
        registration_trend = cursor.fetchall()
        
        # Get application status distribution
        cursor.execute('''
            SELECT status, COUNT(*) as count
            FROM job_applications
            GROUP BY status
        ''')
        application_stats = cursor.fetchall()
        
        stats = {
            'total_users': total_users,
            'active_resumes': active_resumes,
            'total_applications': total_applications,
            'premium_users': premium_users,
            'registration_trend': registration_trend,
            'application_stats': application_stats
        }
        
        return render_template('admin/dashboard.html',
                             stats=stats,
                             recent_users=recent_users,
                             recent_logs=recent_logs)
    
    except Exception as e:
        print(f"Error in admin dashboard: {str(e)}")
        flash('An error occurred while loading the dashboard.', 'error')
        return redirect(url_for('welcome'))
    finally:
        cursor.close()
        conn.close()

@app.route('/admin/users')
@admin_required
def admin_users():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Get all users with their stats
        cursor.execute('''
            SELECT 
                u.*,
                COUNT(DISTINCT r.id) as resume_count,
                COUNT(DISTINCT ja.id) as application_count,
                COALESCE(ua.resume_score, 0) as resume_score,
                COALESCE(ua.profile_views, 0) as profile_views
            FROM users u
            LEFT JOIN resumes r ON u.id = r.user_id
            LEFT JOIN job_applications ja ON u.id = ja.user_id
            LEFT JOIN user_analytics ua ON u.id = ua.user_id
            GROUP BY u.id
            ORDER BY u.created_at DESC
        ''')
        users = cursor.fetchall()
        
        return render_template('admin/users.html', users=users)
    except Exception as e:
        print(f"Error in admin users: {str(e)}")
        flash('An error occurred while loading users.', 'error')
        return redirect(url_for('admin_dashboard'))
    finally:
        cursor.close()
        conn.close()

@app.route('/admin/user/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def admin_user_detail(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        if request.method == 'POST':
            # Update user details
            account_type = request.form.get('account_type')
            is_active = request.form.get('is_active') == 'true'
            
            cursor.execute('''
                UPDATE users 
                SET account_type = %s
                WHERE id = %s
            ''', (account_type, user_id))
            conn.commit()
            
            flash('User updated successfully.', 'success')
        
        # Get user details with all related information
        cursor.execute('''
            SELECT 
                u.*,
                COUNT(DISTINCT r.id) as resume_count,
                COUNT(DISTINCT ja.id) as application_count,
                COALESCE(ua.resume_score, 0) as resume_score,
                COALESCE(ua.profile_views, 0) as profile_views
            FROM users u
            LEFT JOIN resumes r ON u.id = r.user_id
            LEFT JOIN job_applications ja ON u.id = ja.user_id
            LEFT JOIN user_analytics ua ON u.id = ua.user_id
            WHERE u.id = %s
            GROUP BY u.id
        ''', (user_id,))
        user = cursor.fetchone()
        
        if not user:
            flash('User not found.', 'error')
            return redirect(url_for('admin_users'))
        
        # Get user's resumes
        cursor.execute('''
            SELECT * FROM resumes 
            WHERE user_id = %s 
            ORDER BY upload_date DESC
        ''', (user_id,))
        resumes = cursor.fetchall()
        
        # Get user's job applications
        cursor.execute('''
            SELECT * FROM job_applications 
            WHERE user_id = %s 
            ORDER BY apply_date DESC
        ''', (user_id,))
        applications = cursor.fetchall()
        
        # Get user's skills
        cursor.execute('''
            SELECT s.name, us.proficiency_level
            FROM skills s
            JOIN user_skills us ON s.id = us.skill_id
            WHERE us.user_id = %s
        ''', (user_id,))
        skills = cursor.fetchall()
        
        return render_template('admin/user_detail.html',
                             user=user,
                             resumes=resumes,
                             applications=applications,
                             skills=skills)
    except Exception as e:
        print(f"Error in admin user detail: {str(e)}")
        flash('An error occurred while loading user details.', 'error')
        return redirect(url_for('admin_users'))
    finally:
        cursor.close()
        conn.close()

@app.route('/admin/analytics')
@admin_required
def admin_analytics():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Get total users
        cursor.execute('SELECT COUNT(*) as count FROM users')
        total_users = cursor.fetchone()['count']
        
        # Get active resumes
        cursor.execute('SELECT COUNT(*) as count FROM resumes')
        active_resumes = cursor.fetchone()['count']
        
        # Get premium users
        cursor.execute("SELECT COUNT(*) as count FROM users WHERE account_type = 'premium'")
        premium_users = cursor.fetchone()['count']
        
        # Get average resume score
        cursor.execute('SELECT AVG(ats_score) as avg_score FROM resumes')
        avg_score = cursor.fetchone()['avg_score'] or 0
        
        # Get user growth data (last 7 days)
        cursor.execute('''
            SELECT DATE(created_at) as date, COUNT(*) as count 
            FROM users 
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            GROUP BY DATE(created_at)
            ORDER BY date
        ''')
        growth_data = cursor.fetchall()
        
        # Get resume score distribution
        cursor.execute('''
            SELECT 
                CASE 
                    WHEN ats_score >= 90 THEN '90-100'
                    WHEN ats_score >= 80 THEN '80-89'
                    WHEN ats_score >= 70 THEN '70-79'
                    WHEN ats_score >= 60 THEN '60-69'
                    ELSE 'Below 60'
                END as range,
                COUNT(*) as count
            FROM resumes
            GROUP BY range
            ORDER BY range DESC
        ''')
        score_distribution = cursor.fetchall()
        
        # Get user activity by hour (last 24 hours)
        cursor.execute('''
            SELECT HOUR(created_at) as hour, COUNT(*) as count
            FROM user_analytics
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            GROUP BY HOUR(created_at)
            ORDER BY hour
        ''')
        activity_data = cursor.fetchall()
        
        # Calculate growth percentages
        cursor.execute('''
            SELECT COUNT(*) as count 
            FROM users 
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 14 DAY)
            AND created_at < DATE_SUB(NOW(), INTERVAL 7 DAY)
        ''')
        previous_week_users = cursor.fetchone()['count']
        current_week_users = sum(day['count'] for day in growth_data)
        user_growth = ((current_week_users - previous_week_users) / previous_week_users * 100) if previous_week_users > 0 else 0
        
        # Prepare data for charts
        stats = {
            'total_users': total_users,
            'active_resumes': active_resumes,
            'premium_users': premium_users,
            'avg_resume_score': round(avg_score, 1),
            'user_growth': round(user_growth, 1),
            'resume_growth': 5.2,  # Placeholder
            'premium_growth': 3.8,  # Placeholder
            'score_growth': 2.1,  # Placeholder
            'growth_labels': [d['date'].strftime('%Y-%m-%d') for d in growth_data],
            'growth_data': [d['count'] for d in growth_data],
            'score_labels': [d['range'] for d in score_distribution],
            'score_data': [d['count'] for d in score_distribution],
            'activity_labels': [f"{d['hour']:02d}:00" for d in activity_data],
            'activity_data': [d['count'] for d in activity_data]
        }
        
        return render_template('admin/analytics.html', stats=stats)
    except Exception as e:
        print(f"Error in admin analytics: {str(e)}")
        return "Error loading analytics", 500
    finally:
        cursor.close()
        conn.close()

@app.route('/admin/logs')
@admin_required
def admin_logs():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Get filter parameters
        level = request.args.get('level')
        date_range = request.args.get('date_range', '24h')
        search = request.args.get('search', '')
        page = int(request.args.get('page', 1))
        per_page = 20
        
        # Build the base query
        query = 'SELECT * FROM system_logs WHERE 1=1'
        params = []
        
        # Apply filters
        if level:
            query += ' AND level = %s'
            params.append(level)
        
        if date_range != 'all':
            interval = {
                '24h': 'INTERVAL 24 HOUR',
                '7d': 'INTERVAL 7 DAY',
                '30d': 'INTERVAL 30 DAY'
            }.get(date_range, 'INTERVAL 24 HOUR')
            query += f' AND timestamp >= DATE_SUB(NOW(), {interval})'
        
        if search:
            query += ' AND (message LIKE %s OR details LIKE %s)'
            search_param = f'%{search}%'
            params.extend([search_param, search_param])
        
        # Get total count for pagination
        count_query = f'SELECT COUNT(*) as count FROM ({query}) as filtered_logs'
        cursor.execute(count_query, params)
        total_logs = cursor.fetchone()['count']
        total_pages = (total_logs + per_page - 1) // per_page
        
        # Add pagination
        query += ' ORDER BY timestamp DESC LIMIT %s OFFSET %s'
        params.extend([per_page, (page - 1) * per_page])
        
        # Execute final query
        cursor.execute(query, params)
        logs = cursor.fetchall()
        
        return render_template('admin/logs.html',
                             logs=logs,
                             current_page=page,
                             total_pages=total_pages)
    except Exception as e:
        print(f"Error in admin logs: {str(e)}")
        return "Error loading logs", 500
    finally:
        cursor.close()
        conn.close()

# Function to log system events
def log_system_event(level, message, source, details=None):
    """
    Log a system event to the database.
    
    Args:
        level (str): Log level ('info', 'warning', 'error', 'success')
        message (str): Main log message
        source (str): Source of the log (e.g., 'admin', 'user', 'system')
        details (str, optional): Additional details about the event
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT INTO system_logs (level, message, source, details, timestamp)
            VALUES (%s, %s, %s, %s, NOW())
        ''', (level, message, source, details))
        conn.commit()
    except Exception as e:
        print(f"Error logging system event: {str(e)}")
    finally:
        cursor.close()
        conn.close()

# Create system_logs table if it doesn't exist
def create_logs_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                level VARCHAR(10) NOT NULL,
                message TEXT NOT NULL,
                source VARCHAR(50) NOT NULL,
                details TEXT,
                timestamp DATETIME NOT NULL,
                INDEX idx_timestamp (timestamp),
                INDEX idx_level (level),
                INDEX idx_source (source)
            )
        ''')
        conn.commit()
    except Exception as e:
        print(f"Error creating system_logs table: {str(e)}")
    finally:
        cursor.close()
        conn.close()

# Call this function when the application starts
create_logs_table()

@app.route('/profile')
@login_required
def profile():
    try:
        user_id = session.get('user_id')
        if not user_id:
            flash('Please login first', 'error')
            return redirect(url_for('login'))
            
        conn = get_db_connection()
        if not conn:
            flash('Database connection failed', 'error')
            return redirect(url_for('dashboard'))
            
        cursor = conn.cursor(dictionary=True)
        
        # Check if user is admin
        cursor.execute('SELECT * FROM admins WHERE id = %s', (user_id,))
        admin = cursor.fetchone()
        
        if admin:
            # Admin profile code remains the same
            cursor.execute('''
                SELECT COUNT(*) as total_actions 
                FROM admin_activity_log 
                WHERE admin_id = %s
            ''', (user_id,))
            total_actions = cursor.fetchone()['total_actions']
            
            cursor.execute('''
                SELECT COUNT(DISTINCT user_id) as users_managed 
                FROM user_activity_log 
                WHERE admin_id = %s
            ''', (user_id,))
            users_managed = cursor.fetchone()['users_managed']
            
            cursor.execute('''
                SELECT COALESCE(last_login, created_at) as last_login, 
                       DATEDIFF(CURRENT_DATE, created_at) as active_days 
                FROM admins 
                WHERE id = %s
            ''', (user_id,))
            admin_info = cursor.fetchone()
            
            # Fetch recent activities
            cursor.execute('''
                SELECT * FROM admin_activity_log 
                WHERE admin_id = %s 
                ORDER BY timestamp DESC 
                LIMIT 10
            ''', (user_id,))
            activities = cursor.fetchall()
            
            # Fetch access logs
            cursor.execute('''
                SELECT * FROM admin_access_log 
                WHERE admin_id = %s 
                ORDER BY timestamp DESC 
                LIMIT 10
            ''', (user_id,))
            access_logs = cursor.fetchall()
            
            stats = {
                'total_actions': total_actions,
                'users_managed': users_managed,
                'last_login': admin_info['last_login'],
                'active_days': admin_info['active_days']
            }
            
            return render_template('admin/profile.html', 
                                 admin=admin, 
                                 stats=stats, 
                                 activities=activities, 
                                 access_logs=access_logs)
        else:
            # Fetch user data with all fields
            cursor.execute('''
                SELECT u.*, 
                       COUNT(r.id) as resume_count
                FROM users u
                LEFT JOIN resumes r ON u.id = r.user_id
                WHERE u.id = %s
                GROUP BY u.id
            ''', (user_id,))
            user_data = cursor.fetchone()
            
            if not user_data:
                flash('User not found', 'error')
                return redirect(url_for('dashboard'))
            
            # Fetch user analytics data
            cursor.execute('''
                SELECT * FROM user_analytics 
                WHERE user_id = %s
            ''', (user_id,))
            analytics = cursor.fetchone()
            
            if not analytics:
                # If no analytics exist, create default values
                cursor.execute('''
                    INSERT INTO user_analytics 
                    (user_id, resume_score, job_matches, profile_views, applications)
                    VALUES (%s, 0, 0, 0, 0)
                ''', (user_id,))
                conn.commit()
                analytics = {
                    'resume_score': 0,
                    'job_matches': 0,
                    'profile_views': 0,
                    'applications': 0
                }
            
            # Initialize empty lists for skills and applications since tables don't exist
            skills = []
            recent_applications = []
            
            # Set default profile picture path
            if not user_data.get('profile_picture'):
                user_data['profile_picture'] = url_for('static', filename='images/default-profile.png')
            
            return render_template('user_profile.html', 
                                 user=user_data, 
                                 skills=skills, 
                                 analytics=analytics,
                                 recent_applications=recent_applications)
                                 
    except Exception as e:
        print(f"Error in profile route: {str(e)}")
        flash(f'Error loading profile: {str(e)}', 'error')
        return redirect(url_for('dashboard'))
        
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/admin/profile/update', methods=['POST'])
def update_admin_profile():
    if 'user_id' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        if not conn:
            flash('Database connection failed', 'error')
            return redirect(url_for('profile'))
            
        cursor = conn.cursor(dictionary=True)
        
        # Verify user is admin
        cursor.execute('SELECT * FROM admins WHERE id = %s', (user_id,))
        admin = cursor.fetchone()
        if not admin:
            flash('Unauthorized access', 'error')
            return redirect(url_for('dashboard'))
        
        # Validate form data
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        
        if not first_name or not last_name:
            flash('First name and last name are required', 'error')
            return redirect(url_for('profile'))
            
        if not all(c.isalpha() or c.isspace() for c in first_name + last_name):
            flash('Names should only contain letters and spaces', 'error')
            return redirect(url_for('profile'))
            
        if len(first_name) > 50 or len(last_name) > 50:
            flash('Names should be less than 50 characters', 'error')
            return redirect(url_for('profile'))
        
        # Handle profile picture upload
        profile_picture_path = admin['profile_picture']  # Keep existing picture by default
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and file.filename:
                # Validate file type
                if not allowed_file(file.filename):
                    flash('Invalid file type. Allowed types are: PNG, JPG, GIF', 'error')
                    return redirect(url_for('profile'))
                
                # Validate file size (5MB max)
                if len(file.read()) > 5 * 1024 * 1024:  # 5MB in bytes
                    flash('File size too large. Maximum size is 5MB', 'error')
                    return redirect(url_for('profile'))
                file.seek(0)  # Reset file pointer after reading
                
                try:
                    # Ensure the upload directory exists
                    upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'admin_profiles')
                    os.makedirs(upload_dir, exist_ok=True)
                    
                    # Generate unique filename
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    filename = secure_filename(f"admin_{user_id}_{timestamp}_{file.filename}")
                    filepath = os.path.join(upload_dir, filename)
                    
                    # Save the file
                    file.save(filepath)
                    
                    # Delete old profile picture if it exists
                    if profile_picture_path and os.path.exists(profile_picture_path):
                        try:
                            os.remove(profile_picture_path)
                        except Exception as e:
                            print(f"Error deleting old profile picture: {str(e)}")
                    
                    profile_picture_path = filepath
                except Exception as e:
                    flash('Error uploading profile picture', 'error')
                    print(f"Error saving profile picture: {str(e)}")
                    return redirect(url_for('profile'))
        
        # Update the database
        try:
            cursor.execute('''
                UPDATE admins 
                SET first_name = %s, 
                    last_name = %s,
                    profile_picture = %s,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
            ''', (first_name, last_name, profile_picture_path, user_id))
            
            # Log the profile update
            cursor.execute('''
                INSERT INTO admin_activity_log 
                (admin_id, action, details) 
                VALUES (%s, 'Profile Update', 'Updated profile information')
            ''', (user_id,))
            
            conn.commit()
            flash('Profile updated successfully', 'success')
            
        except mysql.connector.Error as e:
            conn.rollback()
            flash('Error updating profile in database', 'error')
            print(f"Database error: {str(e)}")
            return redirect(url_for('profile'))
            
    except Exception as e:
        if conn:
            conn.rollback()
        flash('An unexpected error occurred', 'error')
        print(f"Unexpected error: {str(e)}")
        return redirect(url_for('profile'))
        
    finally:
        if cursor:
            cursor.close()
        if conn:
            try:
                conn.close()
            except Exception as e:
                print(f"Error closing database connection: {str(e)}")
    
    return redirect(url_for('profile'))

@app.route('/user/profile/update', methods=['POST'])
@login_required
def update_user_profile():
    try:
        user_id = session['user_id']
        conn = get_db_connection()
        if not conn:
            flash('Database connection failed', 'error')
            return redirect(url_for('profile'))
            
        cursor = conn.cursor(dictionary=True)
        
        # Get form data with proper validation
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        phone = request.form.get('phone', '').strip()
        linkedin_url = request.form.get('linkedin_url', '').strip()
        github_url = request.form.get('github_url', '').strip()
        
        # Validate required fields
        if not first_name or not last_name:
            flash('First name and last name are required', 'error')
            return redirect(url_for('profile'))
            
        # Validate names (only letters and spaces)
        if not all(c.isalpha() or c.isspace() for c in first_name + last_name):
            flash('Names should only contain letters and spaces', 'error')
            return redirect(url_for('profile'))
            
        # Validate URLs if provided
        if linkedin_url and not linkedin_url.startswith(('http://', 'https://')):
            linkedin_url = 'https://' + linkedin_url
        if github_url and not github_url.startswith(('http://', 'https://')):
            github_url = 'https://' + github_url
            
        # Handle profile picture upload
        profile_picture_path = None
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and file.filename:
                if not allowed_file(file.filename):
                    flash('Invalid file type. Allowed types are: PNG, JPG, GIF', 'error')
                    return redirect(url_for('profile'))
                
                # Validate file size (5MB max)
                if len(file.read()) > 5 * 1024 * 1024:  # 5MB in bytes
                    flash('File size too large. Maximum size is 5MB', 'error')
                    return redirect(url_for('profile'))
                file.seek(0)  # Reset file pointer after reading
                
                try:
                    # Create user_profiles directory if it doesn't exist
                    user_profiles_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'user_profiles')
                    os.makedirs(user_profiles_dir, exist_ok=True)
                    
                    # Generate unique filename
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    filename = secure_filename(f"user_{user_id}_{timestamp}_{file.filename}")
                    filepath = os.path.join(user_profiles_dir, filename)
                    
                    # Save the file
                    file.save(filepath)
                    profile_picture_path = filepath
                    
                except Exception as e:
                    flash('Error uploading profile picture', 'error')
                    print(f"Error saving profile picture: {str(e)}")
                    return redirect(url_for('profile'))
        
        # Update the database
        try:
            if profile_picture_path:
                # Update with new profile picture
                cursor.execute('''
                    UPDATE users 
                    SET first_name = %s, 
                        last_name = %s, 
                        phone = %s, 
                        linkedin_url = %s, 
                        github_url = %s,
                        profile_picture = %s
                    WHERE id = %s
                ''', (first_name, last_name, phone, linkedin_url, github_url, profile_picture_path, user_id))
            else:
                # Update without changing profile picture
                cursor.execute('''
                    UPDATE users 
                    SET first_name = %s, 
                        last_name = %s, 
                        phone = %s, 
                        linkedin_url = %s, 
                        github_url = %s
                    WHERE id = %s
                ''', (first_name, last_name, phone, linkedin_url, github_url, user_id))
            
            conn.commit()
            
            # Update session data
            session['first_name'] = first_name
            session['last_name'] = last_name
            session.modified = True
            
            flash('Profile updated successfully', 'success')
            
        except mysql.connector.Error as e:
            conn.rollback()
            flash('Error updating profile in database', 'error')
            print(f"Database error: {str(e)}")
            return redirect(url_for('profile'))
            
    except Exception as e:
        if conn:
            conn.rollback()
        flash('An unexpected error occurred', 'error')
        print(f"Unexpected error: {str(e)}")
        return redirect(url_for('profile'))
        
    finally:
        if cursor:
            cursor.close()
        if conn:
            try:
                conn.close()
            except Exception as e:
                print(f"Error closing database connection: {str(e)}")
    
    return redirect(url_for('profile'))

# Route to toggle user account type
@app.route('/admin/user/<int:user_id>/toggle-type', methods=['POST'])
@admin_required
def toggle_user_type(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Get current account type
        cursor.execute('SELECT account_type FROM users WHERE id = %s', (user_id,))
        user = cursor.fetchone()
        
        if not user:
            return {'error': 'User not found'}, 404
        
        # Toggle account type
        new_type = 'premium' if user['account_type'] == 'free' else 'free'
        cursor.execute('UPDATE users SET account_type = %s WHERE id = %s', (new_type, user_id))
        conn.commit()
        
        # Log the change
        log_system_event(
            'info',
            f'User {user_id} account type changed to {new_type}',
            'admin'
        )
        
        return {'success': True, 'new_type': new_type}
    except Exception as e:
        print(f"Error toggling user type: {str(e)}")
        return {'error': 'Failed to update user account type'}, 500
    finally:
        cursor.close()
        conn.close()

# Route to toggle user suspension status
@app.route('/admin/user/<int:user_id>/toggle-suspension', methods=['POST'])
@admin_required
def toggle_user_suspension(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Get current suspension status
        cursor.execute('SELECT is_suspended FROM users WHERE id = %s', (user_id,))
        user = cursor.fetchone()
        
        if not user:
            return {'error': 'User not found'}, 404
        
        # Toggle suspension status
        new_status = not user['is_suspended']
        cursor.execute('UPDATE users SET is_suspended = %s WHERE id = %s', (new_status, user_id))
        conn.commit()
        
        # Log the change
        action = 'suspended' if new_status else 'unsuspended'
        log_system_event(
            'warning' if new_status else 'info',
            f'User {user_id} was {action}',
            'admin'
        )
        
        return {'success': True, 'is_suspended': new_status}
    except Exception as e:
        print(f"Error toggling user suspension: {str(e)}")
        return {'error': 'Failed to update user suspension status'}, 500
    finally:
        cursor.close()
        conn.close()

def create_tables():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Create admin_activity_log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admin_activity_log (
                id INT AUTO_INCREMENT PRIMARY KEY,
                admin_id INT NOT NULL,
                action VARCHAR(255) NOT NULL,
                details TEXT,
                ip_address VARCHAR(45),
                user_agent VARCHAR(255),
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE CASCADE
            )
        ''')
        
        # Create admin_access_log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admin_access_log (
                id INT AUTO_INCREMENT PRIMARY KEY,
                admin_id INT NOT NULL,
                action VARCHAR(255) NOT NULL,
                ip_address VARCHAR(45),
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (admin_id) REFERENCES admins(id)
            )
        ''')
        
        # Create user_activity_log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_activity_log (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                admin_id INT,
                action VARCHAR(255) NOT NULL,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (admin_id) REFERENCES admins(id)
            )
        ''')
        
        conn.commit()
        print("Admin activity and access log tables created successfully")
        
    except Exception as e:
        print(f"Error creating admin log tables: {e}")
        conn.rollback()
        
    finally:
        cursor.close()
        conn.close()

# Call create_tables after database initialization
create_tables()

# Route to serve uploaded files
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except Exception as e:
        print(f"Error serving file {filename}: {str(e)}")
        return send_from_directory('static', 'images/default-admin.png')

# Initialize upload directories
def init_upload_dirs():
    upload_dirs = [
        os.path.join(app.config['UPLOAD_FOLDER'], 'admin_profiles'),
        os.path.join(app.config['UPLOAD_FOLDER'], 'user_profiles'),
        os.path.join('static', 'images')
    ]
    for directory in upload_dirs:
        os.makedirs(directory, exist_ok=True)

# Call this after app initialization
init_upload_dirs()

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)