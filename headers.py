import win32com.client
import sqlite3
import os
from sqlite_utils import Database

#init the flyphish.db database
#db = Database(sqlite3.connect("flyphish.db"))
#db["email_headers"].create({
#   "id": str,
#    "Return-Path": str,
#    "From": str,
#   "Authentication-Results": str,
#    "Subject": str,
#    "To": str
#}, pk="id", if_not_exists=True)

desired_headers= ['Return-Path','From','Authentication-Results','Reply-To', 'Subject', 'To', 'Date']
outlook_app = win32com.client.Dispatch("Outlook.Application").GetNamespace("MAPI")
inbox = outlook_app.GetDefaultFolder(6)
messages=inbox.Items
unread_messages = messages.Restrict("[Unread] = True")

print(f"Total Inbox Items: {inbox.Items.Count}")
header_lines = ('')
#output_dir = r
for message in unread_messages:
    print("TEST START")
    print (f"Sender: {message.Sender}")
    headers = message.PropertyAccessor.GetProperty("http://schemas.microsoft.com/mapi/proptag/0x007D001E")
    header_lines = headers.split("\n")
    formatted_headers = {}
    
    #for attachment in message.Attachments:
    #    attachment.SaveAsFile(os.path.join(output_dir, attachment.FileName))
        
    for line in header_lines:
        if ': ' in line:
            key, value = line.split(': ', 1)
            key = key.strip()
            value = value.strip()
            if key in desired_headers:
                formatted_headers[key] = value

    for key, value in formatted_headers.items():
        print(f"{key}: {value}")
