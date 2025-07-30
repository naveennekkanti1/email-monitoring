import imaplib, email
from email.header import decode_header
from bson import ObjectId
from pymongo import MongoClient
from datetime import datetime

client = MongoClient("mongodb+srv://durganaveen:nekkanti@cluster0.8nibi9x.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
db = client.emailmonitoring
emails_col = db.emails
notifications_col = db.notifications
users_col = db.users

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

def fetch_unseen_emails():
    username = 'srmcorporationservices@gmail.com'
    password = 'bxxo qcvd njfj kcsa'
    
    try:
        imap = imaplib.IMAP4_SSL("imap.gmail.com")
        imap.login(username, password)
        imap.select('INBOX')

        status, data = imap.search(None, 'UNSEEN')
        new_emails_count = 0
        
        for num in data[0].split():
            typ, msg_data = imap.fetch(num, '(RFC822)')
            msg = email.message_from_bytes(msg_data[0][1])

            # Decode subject
            decoded = decode_header(msg['Subject'])[0]
            subject, enc = decoded
            if isinstance(subject, bytes):
                subject = subject.decode(enc if enc else 'utf-8', errors='ignore')

            sender = msg.get('From')

            plain_text = ''
            html_body = ''
            images = []

            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    disp = str(part.get('Content-Disposition'))

                    if content_type == 'text/html' and part.get_payload(decode=True):
                        html_body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    elif content_type == 'text/plain' and part.get_payload(decode=True):
                        plain_text = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    elif 'attachment' in disp and part.get_content_maintype() == 'image':
                        images.append(part.get_payload(decode=True))
            else:
                content_type = msg.get_content_type()
                if content_type == 'text/html':
                    html_body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
                else:
                    plain_text = msg.get_payload(decode=True).decode('utf-8', errors='ignore')

            final_body = html_body if html_body else plain_text

            # Check if email already exists
            existing = emails_col.find_one({
                'subject': subject,
                'sender': sender,
                'body': final_body
            })

            if not existing:
                # Insert new email
                email_doc = {
                    'subject': subject,
                    'sender': sender,
                    'body': final_body,
                    'images': images,
                    'assigned_to': None,
                    'reply': None,
                    'reply_by': None,
                    'received_at': datetime.now(),
                    'notified': False
                }
                result = emails_col.insert_one(email_doc)
                new_emails_count += 1
                
                # Create notifications for all midadmins and superadmins
                admins = users_col.find({'role': {'$in': ['midadmin', 'superadmin']}})
                for admin in admins:
                    create_notification(
                        str(admin['_id']),
                        admin['username'],
                        f"New email received from {sender}: {subject[:50]}...",
                        "info",
                        str(result.inserted_id)
                    )

            # Mark email as seen in IMAP
            imap.store(num, '+FLAGS', '\\Seen')

        imap.logout()
        
        # Create summary notification if new emails were found
        if new_emails_count > 0:
            admins = users_col.find({'role': {'$in': ['midadmin', 'superadmin']}})
            for admin in admins:
                create_notification(
                    str(admin['_id']),
                    admin['username'],
                    f"Summary: {new_emails_count} new email(s) received and processed",
                    "success"
                )
        
        print(f"Processed {new_emails_count} new emails")
        return new_emails_count
        
    except Exception as e:
        print(f"Error fetching emails: {e}")
        # Create error notification for admins
        try:
            admins = users_col.find({'role': {'$in': ['midadmin', 'superadmin']}})
            for admin in admins:
                create_notification(
                    str(admin['_id']),
                    admin['username'],
                    f"Error fetching emails: {str(e)}",
                    "error"
                )
        except Exception as notify_error:
            print(f"Error creating error notification: {notify_error}")
        
        return 0

def get_notifications(user_id, limit=50):
    """Get notifications for a specific user"""
    try:
        notifications = notifications_col.find(
            {'user_id': user_id}
        ).sort('created_at', -1).limit(limit)
        return list(notifications)
    except Exception as e:
        print(f"Error fetching notifications: {e}")
        return []

def mark_notification_read(notification_id):
    """Mark a notification as read"""
    try:
        result = notifications_col.update_one(
            {'_id': ObjectId(notification_id)},
            {'$set': {'read': True}}
        )
        return result.modified_count > 0
    except Exception as e:
        print(f"Error marking notification as read: {e}")
        return False

def mark_all_notifications_read(user_id):
    """Mark all notifications as read for a user"""
    try:
        result = notifications_col.update_many(
            {'user_id': user_id, 'read': False},
            {'$set': {'read': True}}
        )
        return result.modified_count
    except Exception as e:
        print(f"Error marking all notifications as read: {e}")
        return 0

def delete_notification(notification_id):
    """Delete a specific notification"""
    try:
        result = notifications_col.delete_one({'_id': ObjectId(notification_id)})
        return result.deleted_count > 0
    except Exception as e:
        print(f"Error deleting notification: {e}")
        return False

def cleanup_old_notifications(days=30):
    """Delete notifications older than specified days"""
    try:
        from datetime import timedelta
        cutoff_date = datetime.now() - timedelta(days=days)
        result = notifications_col.delete_many({'created_at': {'$lt': cutoff_date}})
        print(f"Deleted {result.deleted_count} old notifications")
        return result.deleted_count
    except Exception as e:
        print(f"Error cleaning up notifications: {e}")
        return 0

