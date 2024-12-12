# FlyPhish

FlyPhish is a Python-based tool for scanning email attachments, sender IPs, and domains for potential malicious content. It uses the [VirusTotal API](https://www.virustotal.com/) to analyze files and URLs, providing detailed reports for security analysis.

## Features

- Scans email attachments for malware.
- Analyzes sender IP addresses and domains.
- Processes emails directly from Microsoft Outlook.
- Saves scan results in a structured format.
- Provides a summary of malicious detections.

## Prerequisites

Before using FlyPhish, ensure you have the following:

- **Python 3.8+**
- Microsoft Outlook installed (for email integration).
- A valid [VirusTotal API key](https://www.virustotal.com/).
- Required Python libraries:
  - `requests`
  - `colorama`
  - `pywin32`
  - `argparse`

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/danithen/FlyPhish.git
   cd FlyPhish
   ```

2. Install the dependencies:

   ```bash
   pip install -r requirements.txt
   ```
3. Set up your VirusTotal API key in the script:

   Replace `your_virustotal_api_key_here` in the `API_KEY` variable with your VirusTotal API key.

### Options

- `--amount`: Specify the number of emails to scan (default is 10).
- `--unread`: Only scan unread emails.
- `--clean`: Clear the output directory before running the scan.
- `--output_dir`: Specify the directory to save results (default is `vt_results`).

Example:

```bash
python flyphish.py --amount 5 --unread --output_dir results
```

### Results

Results are saved as JSON files in the specified output directory. Each email's attachments, sender IP, and domain are analyzed and stored separately.

## How It Works

1. **Email Retrieval:**
   FlyPhish connects to Microsoft Outlook and fetches emails based on user-defined criteria (e.g., unread emails).

2. **Attachment Scanning:**
   Email attachments are uploaded to VirusTotal for analysis. The tool waits for the analysis to complete and retrieves detailed results.

3. **Sender Analysis:**
   The sender's IP address and domain are scanned using VirusTotal's API for potential threats.

4. **Results Storage:**
   Scan results are saved in a structured JSON format for easy review and further processing.

## Example Output

A sample result file for an attachment might look like this:

```json
{
  "file_name": "invoice.pdf",
  "data": {
    "harmless": 50,
    "malicious": 2,
    "suspicious": 1
  },
  "email_info": {
    "from": "example@example.com",
    "subject": "Invoice #1234",
    "message_id": "XYZ12345"
  }
}
```

## Cleaning Up

To clear all results from the output directory, run:

```bash
python flyphish.py --clean
```

## Disclaimer

FlyPhish is intended for educational and security analysis purposes only. Ensure you have proper authorization before scanning any emails.

