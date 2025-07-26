import imaplib, email
from email.header import decode_header
from pymongo import MongoClient
client = MongoClient("mongodb+srv://durganaveen:nekkanti@cluster0.8nibi9x.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
db = client.emailmonitoring
emails_col = db.emails

def fetch_unseen_emails():
    username = 'srmcorporationservices@gmail.com'
    password = 'bxxo qcvd njfj kcsa'
    imap = imaplib.IMAP4_SSL("imap.gmail.com")
    imap.login(username, password)
    imap.select('INBOX')

    status, data = imap.search(None, 'UNSEEN')
    for num in data[0].split():
        typ, msg_data = imap.fetch(num, '(RFC822)')
        msg = email.message_from_bytes(msg_data[0][1])

        # Decode subject safely
        decoded = decode_header(msg['Subject'])[0]
        subject, enc = decoded
        if isinstance(subject, bytes):
            subject = subject.decode(enc if enc else 'utf-8', errors='ignore')

        sender = msg.get('From')

        body = ''
        images = []
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                disp = str(part.get('Content-Disposition'))
                if ct == 'text/plain' and part.get_payload(decode=True):
                    body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                elif 'attachment' in disp and part.get_content_maintype() == 'image':
                    images.append(part.get_payload(decode=True))
        else:
            body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')

        # Check if the email already exists by subject, sender, and body
        existing = emails_col.find_one({
            'subject': subject,
            'sender': sender,
            'body': body
        })

        if not existing:
            emails_col.insert_one({
                'subject': subject,
                'sender': sender,
                'body': body,
                'images': images,
                'assigned_to': None,
                'reply': None,
                'reply_by': None
            })

        # ✅ Mark email as seen
        imap.store(num, '+FLAGS', '\\Seen')

    imap.logout()
