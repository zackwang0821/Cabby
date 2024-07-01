import win32com.client as win32

def send_email(subject, body, recipients):
    try:
        outlook = win32.Dispatch('Outlook.Application')
        mail = outlook.CreateItem(0)
        mail.Subject = subject
        mail.Body = body
        mail.To = recipients
        mail.Send()
        print("Pass！")
    except Exception as e:
        print("Fail:", str(e))

subject = "(Test)Your signed files are ready"
body = "Your Microsoft cab sign is ready."
recipients = "iecdockingmcuteam@inventec.com"


send_email(subject, body, recipients)