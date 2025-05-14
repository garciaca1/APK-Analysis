# APK Analysis Tool

This web application automates security analysis of Android Package (APK) files, extracting permissions, checking exported components, scanning hardcoded strings, identifying API levels, and verifying digital signatures. It provides detailed CSV reports and a responsive web interface, designed for security analysts and QA testers.

## Features

- Decompiles APKs using JADX to analyze code and resources.
- Parses AndroidManifest.xml to extract permissions (normal and dangerous), activities, services, and providers.
- Dynamically fetches permission descriptions from the Android Developer website.
- Generates CSV reports by category (permissions, components, sensitive strings) and a ZIP archive of results.
- Displays a summary heatmap in a sortable, interactive web table.
- Runs locally offline, ensuring data privacy.
- Uses a lightweight Flask backend and Bootstrap-based interface for accessibility on basic laptops.

## Demonstration Video

Watch a short video showcasing the tool’s features, including APK upload, analysis, and report generation: [Watch Demo Video](https://github.com/garciaca1/APK-Analysis/blob/main/video/Screencast%20submission.mp4).

## Prerequisites

- Operating System: Windows, macOS, or Linux
- Python: Version 3.8 or higher
- Java Development Kit (JDK): Version 24 or compatible
- JADX: For APK decompilation
- Web Browser: Chrome, Firefox, or similar
- Git: Optional, for cloning the repository

## Setup Instructions

1. **Clone the Repository** (or download the code):
   ```bash
   git clone https://github.com/garciaca1/APK-Analysis.git
   cd apk-analysis-tool
   ```

2. **Install Java**:
   - Download JDK 24 from https://www.oracle.com/java/technologies/downloads/ or https://adoptium.net/.
   - Install using the official installer for your platform.
   - Set the `JAVA_HOME` environment variable to the JDK path (e.g., `C:\Program Files\Java\jdk-24` on Windows).
   - Verify: Run `java -version` in a terminal (should show version 24 or similar).

3. **Install JADX**:
   - Download from https://github.com/skylot/jadx/releases.
   - Extract to a folder (e.g., `C:\jadx` or `~/jadx`).
   - Add the `jadx/bin` folder to your system PATH or set `JADX_PATH` in `app.py`.
   - Verify: Run `jadx --version` in a terminal.

4. **Set Up Python Environment**:
   - Create a virtual environment (recommended):
     ```bash
     python -m venv venv
     source venv/bin/activate  # On Windows: venv\Scripts\activate
     ```
   - Install dependencies from `requirements.txt`:
     ```bash
     pip install -r requirements.txt
     ```
     This installs Flask, Pandas, BeautifulSoup, and Requests.

5. **Configure Web Assets** (optional for offline use):
   - The tool uses Bootstrap 5 and jQuery DataTables via CDN by default (`templates/index.html`).
   - For offline use, download:
     - Bootstrap 5: https://getbootstrap.com/docs/5.3/getting-started/download/
     - jQuery DataTables: https://datatables.net/download/
   - Place files in the `static/` folder and update `index.html` to use local paths.

## Running the Tool

1. **Start the Server**:
   ```bash
   python app.py
   ```
   The app runs at `http://127.0.0.1:5000`.

2. **Use the Web Interface**:
   - Open a browser and visit `http://127.0.0.1:5000`.
   - Drag and drop an APK file to upload.
   - View permissions, components, and sensitive strings in the interactive table.
   - Download CSV reports or a ZIP archive.

3. **Offline Operation**:
   - Use local Bootstrap/DataTables files and a cached permissions list (saved from prior scraping) to run without internet.

## Output Files

- **CSV Reports**: Separate files for permissions, activities, services, providers, and sensitive strings (e.g., `dangerous_permissions.csv`).
- **ZIP Archive**: Contains all CSV reports for easy sharing.
- **Web Heatmap**: Visual summary of analysis results in the interface.

## Configuration

- **File Paths**: Adjust `UPLOAD_FOLDER` and `ANALYSIS_FOLDER` in `app.py` for custom storage.
- **Logging**: Output saved to `app.log` for debugging.
- **Permissions**: Fetched dynamically from https://developer.android.com/reference/android/Manifest.permission; cache locally for offline use.

## Troubleshooting

- **JADX Not Found**: Ensure `jadx/bin` is in PATH or `JADX_PATH` is set in `app.py`.
- **Port Conflict**: Change the port in `app.py` (e.g., `app.run(port=5001)`) if 5000 is in use.
- **Upload Errors**: Use valid APKs under 50 MB, as large files may slow analysis.
- **Web Assets Missing**: Check CDN connectivity or use local Bootstrap/DataTables files for offline mode.

## Security Notes

- Run locally, not publicly, as server-side analysis lacks hardening (e.g., input validation, sandboxing).
- Use test or open-source APKs to avoid legal issues.
- Ensure sensitive data (e.g., hardcoded strings) is handled securely.

## License

For educational and research use only. Contact garciaca1@roehampton.ac.uk for inquiries.

## Tools and Technologies

This project uses the following open-source tools and libraries, with clickable links to their official pages:

- [Bootstrap 5](https://getbootstrap.com/) - Responsive web interface framework.
- [BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/) - Python library for web scraping permission descriptions.
- [Flask](https://flask.palletsprojects.com/) - Python web framework for the backend.
- [JADX](https://github.com/skylot/jadx) - Tool for decompiling APK files.
- [jQuery DataTables](https://datatables.net/) - Library for interactive web tables.
- [Pandas](https://pandas.pydata.org/) - Python library for CSV report generation.
- [Requests](https://requests.readthedocs.io/) - Python library for HTTP requests.