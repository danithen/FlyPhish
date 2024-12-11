import os
import shutil
import time
import requests
import json
import win32com.client  # For accessing Outlook
import re  # For parsing IP from email headers
import argparse
from colorama import Fore, Style  # For colored output


class VirusTotalScanner:
    """
    A class to interact with the VirusTotal API to scan email attachments, sender IPs, and domains.

    Attributes:
        api_key (str): The API key for accessing the VirusTotal API.
        base_url (str): The base URL of the VirusTotal API.
        headers (dict): The headers required for making requests to the VirusTotal API.
        output_dir (str): Directory to save the results.
        malicious_count (int): Counter to track the number of malicious emails found.
    """
    
    def __init__(self, api_key, output_dir="vt_results"):
        """
        Initializes the VirusTotalScanner instance.

        Args:
            api_key (str): The API key for VirusTotal.
            output_dir (str): The directory where results will be saved.
        """
        self.base_url = "https://www.virustotal.com/api/v3"
        self.api_key = api_key
        self.headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)  # Ensure the output directory exists
        self.malicious_count = 0  # Track malicious email count

    def scan_email(self, email_info, attachments):
        """
        Scans an email's attachments, sender IP, and domain using VirusTotal.

        Args:
            email_info (dict): Information about the email (e.g., sender, subject).
            attachments (list): A list of attachment files (name, bytes).
        """
        email_folder = os.path.join(self.output_dir, f"{email_info['message_id']}")
        os.makedirs(email_folder, exist_ok=True)

        malicious_found = False

        # Scan attachments
        for file_name, file_bytes in attachments:
            scan_result = self.scan_attachment(file_bytes, email_info, file_name, output_dir=email_folder)
            if scan_result and scan_result.get('malicious', 0) > 0:
                malicious_found = True

        # Scan sender IP and domain
        sender_domain = email_info["from"].split("@")[1] if "@" in email_info["from"] else "N/A"
        sender_ip = email_info.get("ip", "N/A")
        if sender_ip != "N/A":
            self.scan_ip(sender_ip, email_folder)
        self.scan_domain(sender_domain, email_folder)

        # Update malicious count
        if malicious_found:
            self.malicious_count += 1

    def scan_attachment(self, file_bytes, email_info, file_name, output_dir):
        """
        Scans an email attachment using the VirusTotal API.

        Args:
            file_bytes (bytes): The attachment's file bytes.
            email_info (dict): Information about the email.
            file_name (str): The name of the attachment.
            output_dir (str): Directory to save the results.

        Returns:
            dict: The analysis results of the attachment.
        """
        print(f"Scanning attachment: {file_name}")
        scan_id = self.upload_bytes(file_bytes, file_name)
        if not scan_id:
            print(f"Failed to upload attachment: {file_name}")
            return None

        formatted_stats = self.get_analysis_results(scan_id, file_name, email_info)
        if formatted_stats:
            self.save_results(file_name, formatted_stats, email_info, output_dir)
            return formatted_stats
        return None

    def scan_ip(self, ip_address, output_dir):
        """
        Scans the sender's IP address using the VirusTotal API.

        Args:
            ip_address (str): The IP address to scan.
            output_dir (str): Directory to save the results.
        """
        print(f"Scanning IP: {ip_address}")
        url = f"{self.base_url}/ip_addresses/{ip_address}"
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            data = response.json()
            self.save_results(f"{ip_address}_ip_scan", data, {}, output_dir)
        except Exception as e:
            print(f"Error scanning IP: {e}")

    def scan_domain(self, domain, output_dir):
        """
        Scans the sender's domain using the VirusTotal API.

        Args:
            domain (str): The domain to scan.
            output_dir (str): Directory to save the results.
        """
        print(f"Scanning domain: {domain}")
        url = f"{self.base_url}/domains/{domain}"
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            data = response.json()
            self.save_results(f"{domain}_domain_scan", data, {}, output_dir)
        except Exception as e:
            print(f"Error scanning domain: {e}")

    def upload_bytes(self, file_bytes, file_name):
        """
        Uploads a file to VirusTotal for scanning.

        Args:
            file_bytes (bytes): The content of the file to be uploaded.
            file_name (str): The name of the file.

        Returns:
            str: The ID of the scan if successful, otherwise None.
        """
        url = f"{self.base_url}/files"
        try:
            files = {"file": (file_name, file_bytes, "application/octet-stream")}
            response = requests.post(url, files=files, headers=self.headers)
            response.raise_for_status()
            data = response.json()
            return data["data"]["id"]
        except Exception as e:
            print(f"Error uploading bytes: {e}")
            return None

    def get_analysis_results(self, scan_id, file_name, email_info):
        """
        Retrieves the analysis results of a file from VirusTotal.

        Args:
            scan_id (str): The scan ID for the file.
            file_name (str): The name of the file being analyzed.
            email_info (dict): Information about the email.

        Returns:
            dict: The analysis results if available.
        """
        url = f"{self.base_url}/analyses/{scan_id}"
        for _ in range(50):  # 50 retries with 10-second intervals
            try:
                response = requests.get(url, headers=self.headers)
                response.raise_for_status()
                data = response.json()
                status = data["data"]["attributes"].get("status", "")
                if status == "completed":
                    stats = data["data"]["attributes"].get("stats", {})
                    return stats
                time.sleep(10)
            except Exception as e:
                print(f"Error retrieving analysis results: {e}")
        return None

    def save_results(self, file_name, data, email_info, output_dir):
        """
        Saves the scan results to a file.

        Args:
            file_name (str): The name of the file where results will be saved.
            data (dict): The data to save.
            email_info (dict): Information about the email.
            output_dir (str): Directory to save the results.
        """
        output_path = os.path.join(output_dir, f"{file_name}.json")
        result = {
            "file_name": file_name,
            "data": data,
            "email_info": email_info
        }
        with open(output_path, "w") as f:
            json.dump(result, f, indent=4)
        print(f"Results saved to {output_path}")


def extract_sender_ip(message):
    """
    Extracts the sender's IP address from the message headers.

    Args:
        message (object): The Outlook message object.

    Returns:
        str: The sender's IP address, or "N/A" if not found.
    """
    try:
        headers = message.PropertyAccessor.GetProperty("http://schemas.microsoft.com/mapi/proptag/0x007D001E")
        match = re.search(r"Received: from.*\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]", headers)
        return match.group(1) if match else "N/A"
    except Exception as e:
        print(f"Error extracting sender IP: {e}")
        return "N/A"


def fetch_outlook_emails(scanner, amount_to_scan, unread_only=False):
    """
    Fetches emails from Outlook and scans them for malicious content.

    Args:
        scanner (VirusTotalScanner): The instance of the VirusTotalScanner to use for scanning.
        amount_to_scan (int): The number of emails to scan.
        unread_only (bool): If True, only unread emails will be scanned.
    """
    outlook = win32com.client.Dispatch("Outlook.Application").GetNamespace("MAPI")
    inbox = outlook.GetDefaultFolder(6)  # Inbox folder
    messages = inbox.Items
    total = 0

    # If unread_only is True, filter for unread messages
    if unread_only:
        messages = messages.Restrict("[Unread] = True")

    for message in messages:
        if total < amount_to_scan:
            email_info = {
                "from": message.SenderEmailAddress,
                "subject": message.Subject,
                "message_id": message.EntryID,
                "ip": extract_sender_ip(message),
            }

            # Fetch attachments
            attachments = []
            temp_dir = "temp"
            os.makedirs(temp_dir, exist_ok=True)
            for attachment in message.Attachments:
                file_name = attachment.FileName
                file_path = os.path.join(temp_dir, file_name)
                try:
                    attachment.SaveAsFile(file_path)
                    with open(file_path, "rb") as f:
                        attachments.append((file_name, f.read()))
                except Exception as e:
                    print(f"Error saving or reading attachment: {e}")

            # Scan email content
            scanner.scan_email(email_info, attachments)

            # Cleanup temp files
            for file_name in os.listdir(temp_dir):
                os.remove(os.path.join(temp_dir, file_name))

            total += 1


def display_malicious_count(scanner, total_scanned):
    """
    Displays the number of malicious emails detected.

    Args:
        scanner (VirusTotalScanner): The instance of the VirusTotalScanner.
        total_scanned (int): The total number of emails scanned.
    """
    if scanner.malicious_count == 0:
        print(f"{Fore.GREEN}No malicious emails detected out of {total_scanned}.{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}{scanner.malicious_count} malicious emails detected out of {total_scanned}.{Style.RESET_ALL}")


def clean_output_folder(path):
    """
    Cleans the output folder by deleting all files in it.

    Args:
        path (str): The directory path to clean.
    """
    if os.path.exists(path):
        shutil.rmtree(path)


if __name__ == "__main__":
    """
    Main entry point for the script. Handles command-line arguments, scans emails, and displays results.
    """
    API_KEY = "your_virustotal_api_key_here"
    parser = argparse.ArgumentParser("Email Scanner")
    parser.add_argument("--amount", help="Amount of emails to scan", type=int, default=10)
    parser.add_argument("--unread", help="Filter unread emails only", action="store_true")
    parser.add_argument("--clean", help="Clean results folder", action="store_true")
    parser.add_argument("--output_dir",
