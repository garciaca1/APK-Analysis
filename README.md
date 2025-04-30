# APK Analyzer

This web application allows users to upload one or more APK files and performs a detailed security analysis including:

- Extracting permissions (normal and dangerous)
- Checking for exported components (activities, services, providers)
- Scanning for hardcoded strings
- Identifying the API level and digital signature of the APK
- Viewing and downloading detailed CSV and ZIP reports

## 🔧 Features
- APK decompilation using JADX
- AndroidManifest.xml parsing
- Dynamic fetching of Android permission descriptions from the official Android Developer site
- CSV generation and breakdown by type (permissions, services, providers, etc.)
- Fully responsive Bootstrap-based web UI

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- [JADX](https://github.com/skylot/jadx) installed and added to your system PATH or configured in `app.py` (`JADX_PATH`)

### Install dependencies

```bash
pip install -r requirements.txt
```

### Run the app

```bash
python app.py
```

Visit [http://localhost:5000](http://localhost:5000) in your browser.

### Customize

- `UPLOAD_FOLDER` and `ANALYSIS_FOLDER` in `app.py` control file storage paths.
- Logging output is written to `app.log`.
- Permissions are dynamically fetched from the Android Developer page at runtime.

## 📁 Output Files

Each APK analyzed generates:
- CSV files with structured reports
- ZIP archive of all analysis results
- A summary heatmap shown in the web interface

## 🛡️ Security Notes

This tool runs server-side analysis, so avoid deploying it publicly without security hardening (input validation, auth, sandboxing decompiler, etc.)

## 📜 License

This project is intended for educational and research use only.
