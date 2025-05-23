from flask_mail import Message
from apps.__init__ import mail  # Adjust the import path

def send_reset_email(user):
    msg = Message(
        subject="Password Reset Request",
        recipients=[user.email],
        body=f"""To reset your password, visit the following link:
http://your-domain.com/reset_password/{user.reset_token}

If you did not request a password reset, ignore this email.
"""
    )
    mail.send(msg)