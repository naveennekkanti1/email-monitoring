from flask import Flask, render_template, request, redirect, url_for, session, flash
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from email_utils import fetch_unseen_emails
from bson.objectid import ObjectId
import base64
import smtplib
import ssl
from email.message import EmailMessage
import re

SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 465
SMTP_USERNAME = 'srmcorporationservices@gmail.com'         
SMTP_PASSWORD = 'bxxo qcvd njfj kcsa'            

app = Flask(__name__)
app.secret_key = 'your-secret-key'

# MongoDB setup
client = MongoClient("mongodb://127.0.0.1:27017/?directConnection=true&serverSelectionTimeoutMS=2000&appName=mongosh+2.5.60")
db = client.emailmonitoring
users_col = db.users
emails_col = db.emails

def is_valid_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        u = users_col.find_one({'username': request.form['username']})
        if u and check_password_hash(u['password'], request.form['password']):
            session['user'] = {'username': u['username'], 'role': u['role'], 'id': str(u['_id'])}
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid username or password'
    return render_template('login.html', error=error)

# New helper function to compute analytics per admin
from collections import defaultdict

def compute_admin_analytics():
    analytics = defaultdict(lambda: {'assigned': 0, 'replied': 0, 'pending': 0, 'emails': []})
    admins = users_col.find({'role': 'admin'})
    for admin in admins:
        username = admin['username']
        assigned_emails = list(emails_col.find({'assigned_to': username}))
        for email in assigned_emails:
            analytics[username]['assigned'] += 1
            analytics[username]['emails'].append(email)
            if 'reply' in email and email['reply']:
                analytics[username]['replied'] += 1
            else:
                analytics[username]['pending'] += 1
    return analytics

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))

    u = session['user']

    if u['role'] in ['superadmin', 'midadmin']:
        emails = list(emails_col.find())
        admins = list(users_col.find({'role': 'admin'}))
        analytics = {}
        for admin in admins:
            assigned = list(emails_col.find({'assigned_to': admin['username']}))
            analytics[admin['username']] = {
                'assigned': len(assigned),
                'replied': sum(1 for e in assigned if e.get('reply')),
                'pending': sum(1 for e in assigned if not e.get('reply')),
                'emails': assigned
            }
        return render_template('dashboard.html', user=u, emails=emails, admins=admins, analytics=analytics, notifications=[])

    elif u['role'] == 'admin':
        emails = list(emails_col.find({'assigned_to': u['username']}))
        notifications = list(emails_col.find({'assigned_to': u['username'], 'notified': False}))
        return render_template('dashboard.html', user=u, emails=emails, admins=[], analytics={}, notifications=notifications)

@app.route('/mark-notified', methods=['POST'])
def mark_notified():
    if 'user' in session and session['user']['role'] == 'admin':
        emails_col.update_many(
            {'assigned_to': session['user']['username'], 'notified': False},
            {'$set': {'notified': True}}
        )
    return ('', 204)

@app.route('/fetch')
def fetch():
    fetch_unseen_emails()
    return redirect(url_for('dashboard'))

@app.route('/email/<email_id>', methods=['GET', 'POST'])
def view_email(email_id):
    email_doc = emails_col.find_one({'_id': ObjectId(email_id)})
    if request.method == 'POST':
        if session['user']['role'] == 'admin' and email_doc['assigned_to'] == session['user']['username']:
            reply_text = request.form['reply']
            emails_col.update_one({'_id': ObjectId(email_id)},
                                  {'$set': {'reply': reply_text, 'reply_by': session['user']['username']}})
            # Send reply to original sender
            send_email(email_doc['sender'], email_doc['subject'], reply_text)

        return redirect(url_for('dashboard'))
    return render_template('view_email.html', email=email_doc, user=session['user'])

@app.template_filter('b64encode')
def b64encode_filter(data):
    if data:
        return base64.b64encode(data).decode('utf-8')
    return ''

@app.route('/assign/<email_id>', methods=['POST'])
def assign_email(email_id):
    if session.get('user', {}).get('role') == 'midadmin':
        target_user = request.form['username']
        emails_col.update_one(
            {'_id': ObjectId(email_id)},
            {'$set': {'assigned_to': target_user, 'notified': False}}  # Add notified flag
        )
    return redirect(url_for('dashboard'))

def send_welcome_email(username, password):
    """Send welcome email with login credentials to new user"""
    try:
        if not is_valid_email(username):
            raise ValueError("Invalid email address")
            
        msg = EmailMessage()
        msg['From'] = SMTP_USERNAME
        msg['To'] = username
        msg['Subject'] = "Welcome to Email Monitoring System - Your Login Credentials"
        
        body = f"""
Welcome to the Email Monitoring System!

Your account has been successfully created. Here are your login credentials:

Username: {username}
Password: {password}

Please log in to the system using these credentials and change your password after your first login for security purposes.

System URL: [Your System URL Here]

If you have any questions or need assistance, please contact your system administrator.

Best regards,
Email Monitoring System Team
        """
        
        msg.set_content(body)

        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Failed to send welcome email: {e}")
        return False

@app.route('/manage-users', methods=['GET', 'POST'])
def manage_users():
    if session.get('user', {}).get('role') != 'superadmin':
        return redirect(url_for('dashboard'))

    error = None
    success = None
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        
        # Validate email format for username
        if not is_valid_email(username):
            error = 'Username must be a valid email address.'
        else:
            existing_user = users_col.find_one({'username': username})
            if existing_user:
                error = 'User already exists.'
            else:
                # Create user
                users_col.insert_one({
                    'username': username,
                    'password': generate_password_hash(password),
                    'role': role
                })
                
                # Send welcome email
                if send_welcome_email(username, password):
                    success = f'User {username} created successfully and welcome email sent!'
                else:
                    success = f'User {username} created successfully, but failed to send welcome email.'

    users = list(users_col.find())
    return render_template('manage_users.html', users=users, error=error, success=success)

def send_email(to_email, subject, body):
    msg = EmailMessage()
    msg['From'] = SMTP_USERNAME
    msg['To'] = to_email
    msg['Subject'] = f"RE: {subject}"
    msg.set_content(body)

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)