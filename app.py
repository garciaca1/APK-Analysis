import os
import subprocess
import xml.etree.ElementTree as ET
import csv
import re
import pandas as pd
import zipfile
import logging
import time
import json
import shutil
import requests
from bs4 import BeautifulSoup
from datetime import datetime
from flask import (
    Flask,
    render_template,
    request,
    send_file,
    flash,
    redirect,
    url_for,
    g,
)
from werkzeug.utils import secure_filename
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


logging.basicConfig(
    filename="app.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "Uploads"
app.config["ANALYSIS_FOLDER"] = "analysis_results"  # Base folder for analysis results
app.config["SECRET_KEY"] = "your-secret-key"  # replace with a secure key later on
app.config["MAX_CONTENT_LENGTH"] = (
    2 * 1024 * 1024 * 1024
)  # 2GB max upload size for the apk files


def fetch_android_permissions():
    """Fetch the official Android permissions list from the Android Developers site with retries."""
    try:
        
        session = requests.Session()
        retries = Retry(
            total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504]
        )
        session.mount("https://", HTTPAdapter(max_retries=retries))

        url = "https://developer.android.com/reference/android/Manifest.permission"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Referer": "https://developer.android.com/",
            "Connection": "keep-alive",
        }
        logging.info(f"Fetching permissions from {url}")
        response = session.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        logging.info(
            f"Received response: {response.status_code}, length: {len(response.text)}"
        )

        soup = BeautifulSoup(response.content, "html.parser")
        permissions = {}

        
        dangerous_permissions = {
            "READ_CALENDAR",
            "WRITE_CALENDAR",
            "CAMERA",
            "READ_CONTACTS",
            "WRITE_CONTACTS",
            "GET_ACCOUNTS",
            "ACCESS_FINE_LOCATION",
            "ACCESS_COARSE_LOCATION",
            "RECORD_AUDIO",
            "READ_PHONE_STATE",
            "CALL_PHONE",
            "READ_CALL_LOG",
            "WRITE_CALL_LOG",
            "ADD_VOICEMAIL",
            "USE_SIP",
            "PROCESS_OUTGOING_CALLS",
            "BODY_SENSORS",
            "SEND_SMS",
            "RECEIVE_SMS",
            "READ_SMS",
            "RECEIVE_WAP_PUSH",
            "RECEIVE_MMS",
            "READ_EXTERNAL_STORAGE",
            "WRITE_EXTERNAL_STORAGE",
            "ACTIVITY_RECOGNITION",
            "ANSWER_PHONE_CALLS",
            "ACCESS_BACKGROUND_LOCATION",
            "READ_MEDIA_AUDIO",
            "READ_MEDIA_IMAGES",
            "READ_MEDIA_VIDEO",
        }

        
        table = soup.find("table", class_="responsive constants")
        if not table:
            logging.error("Could not find permissions table in page")
            raise Exception("Could not find permissions table in page")

        
        for row in table.find_all("tr")[1:]:  
            cols = row.find_all("td")
            if len(cols) < 2:
                logging.warning(
                    f"Skipping row with insufficient columns: {row.text[:100]}"
                )
                continue

            perm_tag = cols[1].find("a")
            description_tag = cols[1].find("p")

            if not perm_tag:
                logging.warning(f"No permission tag found in row: {row.text[:100]}")
                continue

            perm_name = perm_tag.text.strip().replace(
                "\u200b", ""
            )  
            description = (
                description_tag.text.strip()
                if description_tag
                else "No description available."
            )
            level = "Dangerous" if perm_name in dangerous_permissions else "Normal"

            full_perm_name = f"android.permission.{perm_name}"
            permissions[full_perm_name] = {
                "category": level,
                "description": description,
            }
            logging.info(
                f"Extracted permission: {full_perm_name}, Category: {level}, Description: {description[:50]}..."
            )

        if not permissions:
            logging.error("No valid permissions extracted from the table")
            raise Exception("No valid permissions extracted from the table")

        logging.info(f"Successfully fetched {len(permissions)} Android permissions")
        return permissions
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch Android permissions: {str(e)}")
        raise
    except Exception as e:
        logging.error(f"Error parsing Android permissions: {str(e)}")
        raise


def load_permissions():
    """Load permissions by fetching from the Android Developers site."""
    try:
        permissions = fetch_android_permissions()
        logging.info(
            f"Loaded {len(permissions)} permissions from Android Developers site"
        )
        return permissions
    except Exception as e:
        logging.error(f"Failed to load permissions: {e}")
        flash("Failed to fetch Android permissions. Please try again later.", "danger")
        return {}


@app.before_request
def load_permissions_before_request():
    """Load permissions before each request if not already loaded."""
    if not hasattr(g, "permissions"):
        g.permissions = load_permissions()
        g.dangerous_permissions = {
            perm
            for perm, data in g.permissions.items()
            if data["category"] == "Dangerous"
        }
        g.permission_descriptions = {
            perm: data["description"] for perm, data in g.permissions.items()
        }
        logging.info(
            f"Loaded {len(g.permissions)} permissions, {len(g.dangerous_permissions)} dangerous"
        )
        logging.info(
            f"Permission descriptions (first few): {list(g.permission_descriptions.items())[:3]}"
        )


def decompile_apk(apk_path, output_folder):
    """Runs JADX to decompile the APK and logs output."""
    try:
        if not os.path.exists(output_folder):
            os.makedirs(output_folder)
        
        jadx_path = os.getenv("JADX_PATH", "C:\\JADX\\bin\\jadx.bat")
        command = [
            jadx_path,
            "--log-level",
            "ERROR",
            "-d",
            output_folder,
            apk_path,
        ]
        with open(
            os.path.join(output_folder, "jadx_output.log"), "w", encoding="utf-8"
        ) as log_file:
            result = subprocess.run(
                command, stdout=log_file, stderr=log_file, text=True
            )
        if result.returncode != 0:
            message = "JADX encountered errors. Check 'jadx_output.log' in the analysis folder for details."
            logging.warning(message)
            flash(message)
        else:
            message = "Decompilation finished."
            logging.info(message)
        return message
    except Exception as e:
        message = f"Error during decompilation: {e}"
        logging.error(message)
        flash(message)
        return message


def locate_manifest(output_folder):
    """Finds and returns the path to AndroidManifest.xml."""
    for root, _, files in os.walk(output_folder):
        if "AndroidManifest.xml" in files:
            return os.path.join(root, "AndroidManifest.xml")
    logging.error("AndroidManifest.xml not found.")
    return None


def get_api_level(manifest_path):
    """Extracts the target API level (targetSdkVersion) from AndroidManifest.xml."""
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        uses_sdk = root.find("uses-sdk")
        if uses_sdk is not None:
            api_level = uses_sdk.attrib.get(
                "{http://schemas.android.com/apk/res/android}targetSdkVersion"
            )
            return api_level if api_level else "Unknown"
        return "Unknown"
    except ET.ParseError as e:
        logging.error(f"Error reading manifest for API level: {e}")
        return "Unknown"


def get_apk_signature(apk_path):
    """Checks the APK for digital signatures in META-INF/ folder."""
    try:
        with zipfile.ZipFile(apk_path, "r") as apk_zip:
            signature_files = [
                f
                for f in apk_zip.namelist()
                if f.startswith("META-INF/") and f.endswith(".RSA")
            ]
            return (
                ", ".join(signature_files) if signature_files else "No signature found"
            )
    except Exception as e:
        logging.error(f"Error checking APK signature: {e}")
        return "Error checking signature"


def get_manifest_details(manifest_path):
    """Extracts permissions, activities, services, providers, and exported statuses."""
    permissions, activities, providers, services = [], [], [], []
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        for perm in root.findall("uses-permission"):
            perm_name = perm.attrib.get(
                "{http://schemas.android.com/apk/res/android}name"
            )
            if perm_name:
                original_perm_name = perm_name
                
                if not perm_name.startswith("android.permission."):
                    perm_name = "android.permission." + perm_name
                category = (
                    "Dangerous" if perm_name in g.dangerous_permissions else "Normal"
                )
                logging.info(
                    f"Permission extracted: {original_perm_name} -> Normalized: {perm_name}, Category: {category}"
                )
                permissions.append((perm_name, category))
        logging.info(f"Total permissions extracted: {len(permissions)}")
        app_section = root.find("application")
        if app_section:
            for activity in app_section.findall("activity"):
                name = activity.attrib.get(
                    "{http://schemas.android.com/apk/res/android}name", "Unknown"
                )
                exported = activity.attrib.get(
                    "{http://schemas.android.com/apk/res/android}exported"
                )
                exported_status = (
                    "TRUE" if exported and exported.lower() == "true" else "FALSE"
                )
                activities.append((name, exported_status))
            for provider in app_section.findall("provider"):
                name = provider.attrib.get(
                    "{http://schemas.android.com/apk/res/android}name", "Unknown"
                )
                exported = provider.attrib.get(
                    "{http://schemas.android.com/apk/res/android}exported"
                )
                exported_status = (
                    "TRUE" if exported and exported.lower() == "true" else "FALSE"
                )
                providers.append((name, exported_status))
            for service in app_section.findall("service"):
                name = service.attrib.get(
                    "{http://schemas.android.com/apk/res/android}name", "Unknown"
                )
                exported = service.attrib.get(
                    "{http://schemas.android.com/apk/res/android}exported"
                )
                exported_status = (
                    "TRUE" if exported and exported.lower() == "true" else "FALSE"
                )
                services.append((name, exported_status))
    except ET.ParseError as e:
        logging.error(f"Error reading manifest: {e}")
        flash(f"Error reading manifest: {e}")
    return permissions, activities, providers, services


def find_hardcoded_strings(decompiled_folder):
    """Collects hardcoded strings from Java and Kotlin files."""
    strings_found, providers_found_in_strings, services_found_in_strings = [], [], []
    provider_pattern = re.compile(r"provider", re.IGNORECASE)
    service_pattern = re.compile(r"service", re.IGNORECASE)
    for root, _, files in os.walk(decompiled_folder):
        for file in files:
            if file.endswith((".java", ".kt")):
                try:
                    with open(
                        os.path.join(root, file), "r", encoding="utf-8", errors="ignore"
                    ) as file_content:
                        for line in file_content:
                            if '"' in line:
                                strings_found.append(line.strip())
                                if provider_pattern.search(line):
                                    providers_found_in_strings.append(line.strip())
                                if service_pattern.search(line):
                                    services_found_in_strings.append(line.strip())
                except Exception as e:
                    logging.warning(f"Error reading file {file}: {e}")
    return strings_found, providers_found_in_strings, services_found_in_strings


def compute_summary_stats(
    permissions, activities, providers, services, api_level, signature_info
):
    """Computes summary statistics for the component usage heatmap."""
    summary = {
        "API Level": {"Total Found": api_level, "Exported": "–", "Dangerous": "–"},
        "APK Signature": {
            "Total Found": signature_info,
            "Exported": "–",
            "Dangerous": "–",
        },
        "Permissions": {
            "Total Found": len(permissions),
            "Exported": "–",
            "Dangerous": sum(1 for _, cat in permissions if cat == "Dangerous"),
        },
        "Activities": {
            "Total Found": len(activities),
            "Exported": sum(1 for _, exp in activities if exp == "TRUE"),
            "Dangerous": "–",
        },
        "Services": {
            "Total Found": len(services),
            "Exported": sum(1 for _, exp in services if exp == "TRUE"),
            "Dangerous": "–",
        },
        "Providers": {
            "Total Found": len(providers),
            "Exported": sum(1 for _, exp in providers if exp == "TRUE"),
            "Dangerous": "–",
        },
    }
    return summary


def read_csv_to_json(analysis_folder, filename):
    """Reads a CSV file and converts it to a JSON-compatible dictionary."""
    csv_path = os.path.join(analysis_folder, filename)
    try:
        if os.path.exists(csv_path):
            
            with open(csv_path, "r", encoding="utf-8") as f:
                raw_content = f.read()
                logging.info(f"Raw CSV content for {filename}:\n{raw_content[:1000]}")
            df = pd.read_csv(csv_path)
            logging.info(f"CSV {filename} columns: {list(df.columns)}")
            logging.info(f"CSV {filename} first few rows:\n{df.head().to_string()}")
             
            data = df.fillna("").to_dict("records")
            headers = list(df.columns)
            return {"headers": headers, "data": data}
    except Exception as e:
        logging.error(f"Error reading CSV {filename}: {e}")
        flash(f"Error reading CSV {filename}: {e}")
    return {"headers": [], "data": []}


def export_to_csv(
    csv_filename,
    permissions,
    activities,
    providers,
    services,
    strings_found,
    providers_from_strings,
    services_from_strings,
    api_level,
    signature_info,
):
    """Exports the collected data to a CSV file, including API level and signature."""
    try:
        with open(csv_filename, mode="w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Type", "Value", "Exported", "Category"])
            writer.writerow(["API Level", api_level, "N/A", "N/A"])
            writer.writerow(["APK Signature", signature_info, "N/A", "N/A"])
            for perm, category in permissions:
                writer.writerow(["Permission", perm, "N/A", category])
            for act, exported in activities:
                writer.writerow(["Activity", act, exported, "N/A"])
            for prov, exported in providers:
                writer.writerow(["Provider", prov, exported, "N/A"])
            for serv, exported in services:
                writer.writerow(["Service", serv, exported, "N/A"])
            for string in strings_found:
                writer.writerow(["Hardcoded String", string, "N/A", "N/A"])
            for prov_string in providers_from_strings:
                writer.writerow(
                    ["Provider (String Reference)", prov_string, "N/A", "N/A"]
                )
            for serv_string in services_from_strings:
                writer.writerow(
                    ["Service (String Reference)", serv_string, "N/A", "N/A"]
                )
        logging.info(f"CSV file generated: {csv_filename}")
    except Exception as e:
        logging.error(f"Error generating CSV {csv_filename}: {e}")
        flash(f"Error generating CSV: {e}")


def filter_csv(analysis_folder):
    """Filters data into separate CSV files using pandas, with descriptions for all permissions."""
    try:
        df = pd.read_csv(os.path.join(analysis_folder, "apk_analysis.csv"))
        logging.info(f"Initial DataFrame columns: {list(df.columns)}")
        logging.info(f"Initial DataFrame first few rows:\n{df.head().to_string()}")

        df["Exported"] = df["Exported"].astype(str).str.strip().str.upper()
        exported_df = df[
            (df["Exported"] == "TRUE")
            & (df["Type"].isin(["Activity", "Provider", "Service"]))
        ]
        if exported_df.empty:
            logging.info(
                "No exported components found! Check the Exported column formatting."
            )
        exported_df.to_csv(
            os.path.join(analysis_folder, "exported_components.csv"), index=False
        )

        
        permissions_df = df[df["Type"] == "Permission"].copy()
        if not permissions_df.empty:
            logging.info(f"Permissions found: {len(permissions_df)}")
            logging.info(f"Permissions values: {permissions_df['Value'].tolist()}")
            
            permissions_df["Description"] = (
                permissions_df["Value"]
                .map(g.permission_descriptions)
                .fillna("No description available")
            )
            logging.info(
                f"Permissions DataFrame after adding Description:\n{permissions_df.to_string()}"
            )
        else:
            logging.info("No permissions found.")
            permissions_df = pd.DataFrame(
                columns=["Type", "Value", "Exported", "Category", "Description"]
            )
        permissions_df.to_csv(
            os.path.join(analysis_folder, "permissions.csv"), index=False
        )
        logging.info(
            f"Permissions CSV written to: {os.path.join(analysis_folder, 'permissions.csv')}"
        )

        df[df["Type"].str.contains("Provider", na=False, case=False)].to_csv(
            os.path.join(analysis_folder, "providers_only.csv"), index=False
        )
        df[df["Type"].str.contains("Service", na=False, case=False)].to_csv(
            os.path.join(analysis_folder, "services_only.csv"), index=False
        )
        df[df["Type"] == "Hardcoded String"].to_csv(
            os.path.join(analysis_folder, "hardcoded_strings.csv"), index=False
        )
        logging.info(
            "Filtered CSVs have been created successfully in %s", analysis_folder
        )
    except Exception as e:
        logging.error(f"Error filtering CSVs: {e}")
        flash(f"Error filtering CSVs: {e}")


def analyze_apk(filename, apk_path, analysis_folder):
    """Analyze a single APK and return its results."""
    
    if os.path.exists(analysis_folder):
        
        summary_stats_file = os.path.join(analysis_folder, "summary_stats.json")
        if os.path.exists(summary_stats_file):
            with open(summary_stats_file, "r") as f:
                summary_stats = json.load(f)
            flash(
                f"Analysis for {filename} already exists. Retrieving existing results.",
                "info",
            )
            return {
                "apk_name": filename,
                "analysis_folder": os.path.basename(analysis_folder),
                "summary_stats": summary_stats,
                "message": "Analysis retrieved from previous run.",
            }
        else:
            flash(
                f"Analysis folder for {filename} exists but is incomplete. Re-running analysis.",
                "warning",
            )
            shutil.rmtree(analysis_folder)

    
    os.makedirs(analysis_folder, exist_ok=True)

    metadata = {
        "apk_name": filename,
        "timestamp": int(time.time()),
        "analysis_folder": os.path.basename(analysis_folder),
        "status": "started",
    }
    with open(os.path.join(analysis_folder, "metadata.json"), "w") as f:
        json.dump(metadata, f)

    
    decompile_message = decompile_apk(apk_path, analysis_folder)

    
    manifest_path = locate_manifest(analysis_folder)
    if not manifest_path:
        metadata["status"] = "failed"
        metadata["error"] = "AndroidManifest.xml not found"
        with open(os.path.join(analysis_folder, "metadata.json"), "w") as f:
            json.dump(metadata, f)
        flash(
            f"AndroidManifest.xml not found for {filename}. Analysis cannot continue.",
            "danger",
        )
        return None

    
    api_level = get_api_level(manifest_path)
    signature_info = get_apk_signature(apk_path)
    permissions, activities, providers, services = get_manifest_details(manifest_path)
    (
        strings_found,
        providers_from_strings,
        services_from_strings,
    ) = find_hardcoded_strings(analysis_folder)
    export_to_csv(
        os.path.join(analysis_folder, "apk_analysis.csv"),
        permissions,
        activities,
        providers,
        services,
        strings_found,
        providers_from_strings,
        services_from_strings,
        api_level,
        signature_info,
    )
    filter_csv(analysis_folder)
    summary_stats = compute_summary_stats(
        permissions, activities, providers, services, api_level, signature_info
    )

    
    metadata["status"] = "completed"
    with open(os.path.join(analysis_folder, "metadata.json"), "w") as f:
        json.dump(metadata, f)

    
    with open(os.path.join(analysis_folder, "summary_stats.json"), "w") as f:
        json.dump(summary_stats, f)

    return {
        "apk_name": filename,
        "analysis_folder": os.path.basename(analysis_folder),
        "summary_stats": summary_stats,
        "message": "Analysis completed.",
    }


@app.route("/", methods=["GET", "POST"])
def index():
    
    if hasattr(g, "permissions_status"):
        if g.permissions_status == "using_outdated":
            flash(
                "Failed to fetch the latest Android permissions list. Using outdated local permissions.",
                "warning",
            )
        elif g.permissions_status == "using_default":
            flash(
                "Failed to fetch Android permissions list and no local permissions found. Using default permissions list.",
                "warning",
            )
        elif g.permissions_status == "using_default_error":
            flash(
                "Error loading Android permissions. Using default permissions list.",
                "danger",
            )

    if request.method == "POST":
        if "apk_file" not in request.files:
            flash("No file part")
            return redirect(request.url)

        files = request.files.getlist("apk_file")
        if not files or all(file.filename == "" for file in files):
            flash("No files selected")
            return redirect(request.url)

        
        valid_files = [file for file in files if file.filename.endswith(".apk")]
        if not valid_files:
            flash("Please upload valid APK files")
            return redirect(request.url)

        
        analysis_results = []
        for file in valid_files:
            filename = secure_filename(file.filename)
            apk_name = os.path.splitext(filename)[0]  
            analysis_folder_name = apk_name  
            analysis_folder = os.path.join(
                app.config["ANALYSIS_FOLDER"], analysis_folder_name
            )

           
            apk_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(apk_path)

            
            result = analyze_apk(filename, apk_path, analysis_folder)
            if result:
                analysis_results.append(result)

        if not analysis_results:
            flash("No APKs were successfully analyzed.")
            return redirect(request.url)

        
        return render_template("results.html", analysis_results=analysis_results)
    return render_template("index.html")


@app.route("/results/<analysis_folder>")
def show_results(analysis_folder):
    
    analysis_path = os.path.join(app.config["ANALYSIS_FOLDER"], analysis_folder)
    if not os.path.exists(analysis_path):
        flash("Analysis folder not found.", "danger")
        return redirect(url_for("index"))

    
    summary_stats_file = os.path.join(analysis_path, "summary_stats.json")
    if not os.path.exists(summary_stats_file):
        flash("Analysis data not found.", "danger")
        return redirect(url_for("index"))

    with open(summary_stats_file, "r") as f:
        summary_stats = json.load(f)

    
    metadata_file = os.path.join(analysis_path, "metadata.json")
    apk_name = "Unknown APK"
    if os.path.exists(metadata_file):
        with open(metadata_file, "r") as f:
            metadata = json.load(f)
            apk_name = metadata.get("apk_name", "Unknown APK")

    analysis_results = [
        {
            "apk_name": apk_name,
            "analysis_folder": analysis_folder,
            "summary_stats": summary_stats,
            "message": "Analysis completed.",
        }
    ]

    return render_template("results.html", analysis_results=analysis_results)


@app.route("/download/<analysis_folder>/<filename>")
def download_file(analysis_folder, filename):
    file_path = os.path.join(app.config["ANALYSIS_FOLDER"], analysis_folder, filename)
    return send_file(file_path, as_attachment=True)


@app.route("/download_zip/<analysis_folder>")
def download_zip(analysis_folder):
    analysis_path = os.path.join(app.config["ANALYSIS_FOLDER"], analysis_folder)
    if not os.path.exists(analysis_path):
        flash("Analysis folder not found.", "danger")
        return redirect(url_for("index"))

    
    zip_path = os.path.join(
        app.config["ANALYSIS_FOLDER"], f"{analysis_folder}_analysis.zip"
    )
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(analysis_path):
            for file in files:
                if (
                    file != "metadata.json" and file != "summary_stats.json"
                ):  
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, analysis_path)
                    zipf.write(file_path, arcname)

    return send_file(
        zip_path, as_attachment=True, download_name=f"{analysis_folder}_analysis.zip"
    )


@app.route("/delete/<analysis_folder>", methods=["POST"])
def delete_analysis(analysis_folder):
    analysis_path = os.path.join(app.config["ANALYSIS_FOLDER"], analysis_folder)
    try:
        if os.path.exists(analysis_path):
            shutil.rmtree(analysis_path)
            logging.info(f"Deleted analysis folder: {analysis_path}")
            flash("Analysis files deleted successfully.", "success")
        else:
            flash("Analysis folder not found.", "danger")
    except Exception as e:
        logging.error(f"Error deleting analysis folder {analysis_path}: {e}")
        flash(f"Error deleting analysis files: {e}", "danger")
    return redirect(url_for("index"))


@app.route("/view_csv/<analysis_folder>/<filename>")
def view_csv(analysis_folder, filename):
    if not filename.endswith(".csv"):
        flash("Invalid file type. Only CSV files can be viewed.")
        return redirect(url_for("index"))

    csv_data = read_csv_to_json(
        os.path.join(app.config["ANALYSIS_FOLDER"], analysis_folder), filename
    )
    if not csv_data["headers"] or not csv_data["data"]:
        flash(f"No data found in {filename}.")
        return redirect(url_for("index"))

    
    logging.info(f"Viewing CSV {filename} - Headers: {csv_data['headers']}")
    logging.info(f"Viewing CSV {filename} - Number of rows: {len(csv_data['data'])}")
    logging.info(f"Viewing CSV {filename} - First few rows: {csv_data['data'][:5]}")

    title = next(
        (
            title
            for file, title, _ in [
                (
                    "apk_analysis.csv",
                    "Full Analysis Report",
                    "Complete analysis data in CSV format",
                ),
                (
                    "exported_components.csv",
                    "Exported Components",
                    "Activities, providers & services marked as exported",
                ),
                (
                    "permissions.csv",
                    "All Permissions",
                    "All permissions with descriptions (dangerous and normal)",
                ),
                (
                    "providers_only.csv",
                    "Providers",
                    "Content providers declared in the APK",
                ),
                ("services_only.csv", "Services", "Service components from the app"),
                (
                    "hardcoded_strings.csv",
                    "Hardcoded Strings",
                    "String literals found in code",
                ),
            ]
            if file == filename
        ),
        filename,
    )

    return render_template(
        "view_csv.html", csv_data=csv_data, title=title, analysis_folder=analysis_folder
    )


if __name__ == "__main__":
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    os.makedirs(app.config["ANALYSIS_FOLDER"], exist_ok=True)
    app.run(debug=True)
