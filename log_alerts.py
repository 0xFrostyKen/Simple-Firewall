import os
import time
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

last_logged_message = "" #USING GLOBAL VARIABLE FOR MY EMAIL USAGE
ALERT_EMAIL = "satyal.pratik123@gmail.com"
def log_event(message):
    global last_logged_message
    last_logged_message = message

    log_folder = "logs"
    os.makedirs(log_folder, exist_ok=True)
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime())
    log_file = os.path.join(log_folder, f"log_{timestamp}.txt")

    with open(log_file, "a") as file:
        file.write(f"{message}\n")
    #calling the email sending function
    send_email_alert(ALERT_EMAIL)

def send_email_alert(to_email):
    global last_logged_message
    from_email = 'satyal.pratik@gmail.com' #the email address used here should be verified in sendgrid
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    subject = f"Security Alert: {last_logged_message[:50]}..."  # first 50 chars of the message
    message = f"Timestamp: {timestamp}\n\nDetails:\n{last_logged_message}"
    mail = Mail(
        from_email=from_email,
        to_emails=to_email,
        subject=subject,
        plain_text_content=message
    )
    try : 
        sg = SendGridAPIClient(os.getenv('SENDGRID_API_KEY'))
        response = sg.send(mail)
        print(f"Email sent! Status code: {response.status_code}")
    except Exception as e:
        print(f"Error sending email: {e}")

