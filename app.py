from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from email_utils import fetch_unseen_emails, cleanup_old_notifications
from bson.objectid import ObjectId
import base64
import smtplib
import ssl
from email.message import EmailMessage
import re
from datetime import datetime, date
import requests

SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 465
SMTP_USERNAME = 'srmcorporationservices@gmail.com'         
SMTP_PASSWORD = 'bxxo qcvd njfj kcsa'            

app = Flask(__name__)
app.secret_key = 'your-secret-key'

# MongoDB setup
client = MongoClient("mongodb+srv://durganaveen:nekkanti@cluster0.8nibi9x.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
db = client.emailmonitoring
users_col = db.users
emails_col = db.emails
profiles_col = db.profiles
notifications_col = db.notifications  # New collection for notifications

def is_valid_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# New function to create notifications
def create_notification(user_id, username, message, notification_type="info", email_id=None):
    """Create a new notification for a user"""
    try:
        notification = {
            'user_id': user_id,
            'username': username,
            'message': message,
            'type': notification_type,  # info, success, warning, error
            'email_id': email_id,
            'read': False,
            'created_at': datetime.now()
        }
        notifications_col.insert_one(notification)
        return True
    except Exception as e:
        print(f"Error creating notification: {e}")
        return False

# New function to get unread notifications
def get_unread_notifications(username):
    """Get all unread notifications for a user"""
    try:
        notifications = list(notifications_col.find({
            'username': username,
            'read': False
        }).sort('created_at', -1))
        return notifications
    except Exception as e:
        print(f"Error fetching notifications: {e}")
        return []

# New function to mark notifications as read
def mark_notifications_read(username, notification_ids=None):
    """Mark notifications as read"""
    try:
        if notification_ids:
            # Mark specific notifications as read
            notifications_col.update_many(
                {'_id': {'$in': [ObjectId(nid) for nid in notification_ids]}},
                {'$set': {'read': True, 'read_at': datetime.now()}}
            )
        else:
            # Mark all notifications for user as read
            notifications_col.update_many(
                {'username': username, 'read': False},
                {'$set': {'read': True, 'read_at': datetime.now()}}
            )
        return True
    except Exception as e:
        print(f"Error marking notifications as read: {e}")
        return False

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
    notifications = get_unread_notifications(u['username'])

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
        return render_template('dashboard.html', user=u, emails=emails, admins=admins, analytics=analytics, notifications=notifications)

    elif u['role'] == 'admin':
        emails = list(emails_col.find({'assigned_to': u['username']}))
        return render_template('dashboard.html', user=u, emails=emails, admins=[], analytics={}, notifications=notifications)

# New route to get notifications via AJAX
@app.route('/api/notifications')
def get_notifications():
    if 'user' not in session:
        return jsonify([])
    
    notifications = get_unread_notifications(session['user']['username'])
    # Convert ObjectId to string for JSON serialization
    for notification in notifications:
        notification['_id'] = str(notification['_id'])
        if notification.get('email_id'):
            notification['email_id'] = str(notification['email_id'])
    
    return jsonify(notifications)

# New route to mark notifications as read
@app.route('/api/notifications/mark-read', methods=['POST'])
def mark_notifications_read_api():
    if 'user' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'})
    
    data = request.get_json()
    notification_ids = data.get('notification_ids', [])
    
    if mark_notifications_read(session['user']['username'], notification_ids):
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'message': 'Error marking notifications as read'})

# Additional helper function to get user join date
def get_user_join_date(user_id):
    """Get user join date from profile or user document"""
    # First try to get from profile
    profile = profiles_col.find_one({'user_id': user_id})
    if profile and profile.get('join_date'):
        return profile['join_date']
    
    # Fallback to user document
    user = users_col.find_one({'_id': ObjectId(user_id)})
    if user and user.get('join_date'):
        return user['join_date'].strftime('%Y-%m-%d') if hasattr(user['join_date'], 'strftime') else user['join_date']
    
    # Fallback to created_at if available
    if user and user.get('created_at'):
        return user['created_at'].date().strftime('%Y-%m-%d')
    
    return None

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    user = session['user']
    error = None
    success = None
    
    # Get user profile from database
    profile_data = profiles_col.find_one({'user_id': user['id']})
    
    # If no profile exists, create one with join date from user document
    if not profile_data:
        user_doc = users_col.find_one({'_id': ObjectId(user['id'])})
        join_date = None
        
        if user_doc:
            if user_doc.get('join_date'):
                join_date = user_doc['join_date'].strftime('%Y-%m-%d') if hasattr(user_doc['join_date'], 'strftime') else user_doc['join_date']
            elif user_doc.get('created_at'):
                join_date = user_doc['created_at'].date().strftime('%Y-%m-%d')
        
        # Create initial profile
        initial_profile = {
            'user_id': user['id'],
            'name': '',
            'pincode': '',
            'city': '',
            'state': '',
            'district': '',
            'address': '',
            'phone': '',
            'join_date': join_date or date.today().strftime('%Y-%m-%d'),
            'created_at': datetime.now(),
            'updated_at': datetime.now()
        }
        profiles_col.insert_one(initial_profile)
        profile_data = profiles_col.find_one({'user_id': user['id']})
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update_profile':
            try:
                # Prepare profile data
                profile_update = {
                    'user_id': user['id'],
                    'name': request.form.get('name', '').strip(),
                    'pincode': request.form.get('pincode', '').strip(),
                    'city': request.form.get('city', '').strip(),
                    'state': request.form.get('state', '').strip(),
                    'district': request.form.get('district', '').strip(),
                    'address': request.form.get('address', '').strip(),
                    'phone': request.form.get('phone', '').strip(),
                    'join_date': request.form.get('join_date', profile_data.get('join_date', '')),  # Preserve existing join_date
                    'updated_at': datetime.now()
                }
                
                # Handle profile picture upload
                if 'profile_pic' in request.files:
                    file = request.files['profile_pic']
                    if file and file.filename and file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
                        # Convert image to base64
                        profile_update['profile_pic'] = base64.b64encode(file.read()).decode('utf-8')
                
                # Validate required fields
                if not profile_update['name']:
                    error = 'Name is required'
                elif profile_update['pincode'] and len(profile_update['pincode']) != 6:
                    error = 'PIN code must be 6 digits'
                elif profile_update['phone'] and len(profile_update['phone']) != 10:
                    error = 'Phone number must be 10 digits'
                else:
                    # Keep existing profile pic if no new one uploaded
                    if 'profile_pic' not in profile_update and profile_data.get('profile_pic'):
                        profile_update['profile_pic'] = profile_data['profile_pic']
                    
                    profiles_col.update_one(
                        {'user_id': user['id']},
                        {'$set': profile_update}
                    )
                    
                    success = 'Profile updated successfully!'
                    profile_data = profiles_col.find_one({'user_id': user['id']})
                    
            except Exception as e:
                error = f'Error updating profile: {str(e)}'
        
        elif action == 'change_password':
            try:
                current_password = request.form.get('current_password')
                new_password = request.form.get('new_password')
                confirm_password = request.form.get('confirm_password')
                
                # Validate passwords
                if not current_password or not new_password or not confirm_password:
                    error = 'All password fields are required'
                elif new_password != confirm_password:
                    error = 'New password and confirm password do not match'
                elif len(new_password) < 8:
                    error = 'New password must be at least 8 characters long'
                else:
                    # Verify current password
                    user_doc = users_col.find_one({'_id': ObjectId(user['id'])})
                    if user_doc and check_password_hash(user_doc['password'], current_password):
                        # Update password
                        users_col.update_one(
                            {'_id': ObjectId(user['id'])},
                            {'$set': {'password': generate_password_hash(new_password), 'updated_at': datetime.now()}}
                        )
                        success = 'Password changed successfully!'
                    else:
                        error = 'Current password is incorrect'
                        
            except Exception as e:
                error = f'Error changing password: {str(e)}'
    
    # Calculate user statistics
    user_emails = list(emails_col.find({'assigned_to': user['username']}))
    email_count = len(user_emails)
    reply_count = sum(1 for email in user_emails if email.get('reply'))
    
    # Calculate join days
    join_days = 0
    if profile_data and profile_data.get('join_date'):
        try:
            if isinstance(profile_data['join_date'], str):
                join_date = datetime.strptime(profile_data['join_date'], '%Y-%m-%d').date()
            else:
                join_date = profile_data['join_date']
            join_days = (date.today() - join_date).days
        except:
            pass
    
    return render_template('profile.html', 
                         user=user, 
                         profile=profile_data, 
                         error=error, 
                         success=success,
                         email_count=email_count,
                         reply_count=reply_count,
                         join_days=join_days)

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
            
            # Create notification for successful reply
            create_notification(
                session['user']['id'],
                session['user']['username'],
                f"Successfully replied to email: {email_doc['subject'][:50]}...",
                "success",
                email_id
            )

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
        email_doc = emails_col.find_one({'_id': ObjectId(email_id)})
        
        # Update email assignment
        emails_col.update_one(
            {'_id': ObjectId(email_id)},
            {'$set': {'assigned_to': target_user, 'assigned_at': datetime.now()}}
        )
        
        # Get target user details
        target_user_doc = users_col.find_one({'username': target_user})
        if target_user_doc:
            # Create notification for the assigned user
            create_notification(
                str(target_user_doc['_id']),
                target_user,
                f"New email assigned to you: {email_doc['subject'][:50]}...",
                "info",
                email_id
            )
        
        # Create notification for assigning admin
        create_notification(
            session['user']['id'],
            session['user']['username'],
            f"Email assigned to {target_user}: {email_doc['subject'][:50]}...",
            "success",
            email_id
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
        action = request.form.get('action')
        
        if action == 'create':
            username = request.form['username']
            password = request.form['password']
            role = request.form['role']

            if not is_valid_email(username):
                error = 'Username must be a valid email address.'
            else:
                existing_user = users_col.find_one({'username': username})
                if existing_user:
                    error = 'User already exists.'
                else:
                    # Create user with automatic join date
                    current_datetime = datetime.now()
                    user_doc = {
                        'username': username,
                        'password': generate_password_hash(password),
                        'role': role,
                        'created_at': current_datetime,
                        'join_date': current_datetime.date()  # Store join date in user document too
                    }
                    result = users_col.insert_one(user_doc)
                    
                    # Create initial profile with automatic join date
                    initial_profile = {
                        'user_id': str(result.inserted_id),
                        'name': '',
                        'pincode': '',
                        'city': '',
                        'state': '',
                        'district': '',
                        'address': '',
                        'phone': '',
                        'join_date': current_datetime.date().strftime('%Y-%m-%d'),  # Format for form compatibility
                        'created_at': current_datetime,
                        'updated_at': current_datetime
                    }
                    profiles_col.insert_one(initial_profile)
                    
                    # Create welcome notification for new user
                    create_notification(
                        str(result.inserted_id),
                        username,
                        f"Welcome to Email Monitoring System! Your account has been created with role: {role}",
                        "success"
                    )
                    
                    if send_welcome_email(username, password):
                        success = f'User {username} created successfully with join date {current_datetime.date().strftime("%Y-%m-%d")} and welcome email sent!'
                    else:
                        success = f'User {username} created successfully with join date {current_datetime.date().strftime("%Y-%m-%d")}, but failed to send welcome email.'
        
        elif action == 'update':
            user_id = request.form['user_id']
            new_username = request.form['username']
            new_role = request.form['role']
            updated_by = session['user']['username']

            user = users_col.find_one({'_id': ObjectId(user_id)})
            if user:
                changes = []
                update_fields = {}

                if user['username'] != new_username:
                    update_fields['username'] = new_username
                    changes.append(f"Username changed from {user['username']} to {new_username}")

                if user['role'] != new_role:
                    update_fields['role'] = new_role
                    changes.append(f"Role changed from {user['role']} to {new_role}")

                if changes:
                    update_fields['updated_at'] = datetime.now()
                    users_col.update_one({'_id': ObjectId(user_id)}, {'$set': update_fields})
                    
                    # Create notification for updated user
                    create_notification(
                        user_id,
                        new_username,
                        f"Your account has been updated by {updated_by}: {', '.join(changes)}",
                        "info"
                    )
                    
                    send_update_notification(new_username, changes, updated_by)
                    success = f'User updated successfully: {", ".join(changes)}'
                else:
                    success = 'No changes were made.'
    
    users = list(users_col.find())
    return render_template('manage_users.html', users=users, error=error, success=success)

def send_update_notification(to_email, changes, updated_by):
    """Notify the user of their account updates with styled HTML and logo"""
    try:
        msg = EmailMessage()
        msg['From'] = SMTP_USERNAME
        msg['To'] = to_email
        msg['Subject'] = "Account Update Notification - Email Monitoring System"

        # Create change list in HTML
        change_details_html = ''.join(f"<li>{c}</li>" for c in changes)

        # Optional: Base64 image string (or use hosted image URL)
        logo_url = "https://i.imgur.com/Vm7hgH1.jpeg"  # Replace with your image URL or base64 if needed

        html_content = f"""
        <html>
            <body style="font-family: Arial, sans-serif; color: #333; background-color: #f9f9f9; padding: 20px;">
                <div style="max-width: 600px; margin: auto; background: #fff; border: 1px solid #ddd; padding: 20px; border-radius: 8px;">
                    <h2 style="color: #007BFF;">Account Update Notification</h2>
                    <p>Hello <strong>{to_email}</strong>,</p>
                    <p>Your account details have been updated by <strong>{updated_by}</strong>.</p>
                    <p><strong>Changes made:</strong></p>
                    <ul>{change_details_html}</ul>
                    <p>If you did not expect this change, please contact the system administrator immediately.</p>
                    <br>
                    <div style="text-align: center; margin-top: 40px; border-top: 1px solid #eee; padding-top: 10px;">
                        <p style="font-size: 12px; color: #888;">Email Monitoring System</p>
                        <img src="{logo_url}" alt="Email Monitor Logo" style="width: 100px; opacity: 0.8;">
                    </div>
                </div>
            </body>
        </html>
        """

        msg.add_alternative(html_content, subtype='html')

        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)

        return True
    except Exception as e:
        print(f"Failed to send update notification: {e}")
        return False

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
import threading
import time
def background_email_checker():
    while True:
        fetch_unseen_emails()
        time.sleep(5)  # run every 5 minutes

if __name__ == '__main__':
    t = threading.Thread(target=background_email_checker, daemon=True)
    t.start()

    app.run(debug=True)
