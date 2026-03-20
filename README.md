# Email Security Auditor

![Status](https://img.shields.io/badge/Status-Active-green)
![Platform](https://img.shields.io/badge/Platform-Windows-blue)

A desktop application for auditing email security configurations and generating compliance reports.

## Overview

Email Security Auditor helps IT administrators assess and document email security configurations across Microsoft 365 and other email platforms. It generates comprehensive audit reports for compliance purposes.

## Features

- **Email Configuration Audit** - Check SPF, DKIM, DMARC settings
- **Security Assessment** - Evaluate anti-phishing, anti-spam configurations
- **Compliance Reporting** - Generate detailed audit reports
- **Export Capabilities** - Export reports in multiple formats
- **Professional Output** - Clean, branded reports for stakeholders

## Requirements

- Windows 10/11
- Python 3.8+ (if running from source)
- Internet connection for cloud-based checks

## Installation

### Option 1: Run Exe (Recommended)
Download the latest release from the `dist` folder and run `EmailAuditorApp.exe`

### Option 2: Run from Source
```bash
# Clone the repository
git clone https://github.com/Koops1974/EmailAuditorApp.git

# Install dependencies
pip install flask pyinstaller

# Run the application
python app.py
```

## Building from Source

If you want to rebuild the executable:

```bash
pyinstaller app.spec
```

The executable will be created in the `dist` folder.

## Project Structure

```
EmailAuditorApp/
├── app.py              # Main Flask application
├── app.spec           # PyInstaller specification
├── README.md          # This file
├── .gitignore        # Git ignore file
├── Logo.ico          # Application icon
├── Logo.png          # Logo image
├── static/
│   └── Logo.png      # Static assets
└── templates/
    └── index.html    # Web interface template
```

## Usage

1. Launch the application
2. Enter the domain to audit
3. Review the email security settings
4. Generate and export your report

## Author

**DCAD** - Digital Compliance and Audit Services

## License

All rights reserved - DCAD

---

*Professional email security auditing for IT teams.*
