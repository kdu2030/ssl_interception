import sib_api_v3_sdk
from typing import Dict, List

class EmailSender:
    def __init__(self, key_file: str, sender: str = "kdu2030@gmail.com"):
        configuration = sib_api_v3_sdk.Configuration()
        configuration.api_key["api-key"] = self.get_key(key_file)
        self.api_instance = sib_api_v3_sdk.TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(configuration))
        self.sender = {"name": "Kevin Du", "email": sender}
    
    def get_key(self, key_file: str):
        with open(key_file, "r") as file:
            return file.read()
    
    def send_email(self, subject: str, message: str, to: List[Dict]):
        smtp_email = sib_api_v3_sdk.SendSmtpEmail(sender=self.sender, to=to, subject=subject, text_content=message)
        self.api_instance.send_transac_email(smtp_email)
    
    def send_email_to_self(self, subject: str, message: str):
        to = [self.sender]
        smtp_email = sib_api_v3_sdk.SendSmtpEmail(sender=self.sender, to=to, subject=subject, text_content=message)
        self.api_instance.send_transac_email(smtp_email)

def main():
    KEY_FILE = "/home/ubuntu/GitLab/ssl_interception/keys/brevo_key.txt"
    sender = EmailSender(KEY_FILE)
    sender.send_email_to_self("Email Sender Test", "Email Sender Test")

if __name__ == "__main__":
    main()

