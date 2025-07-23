# Author: Enzo LE NAIR
# Version: V1.alpha 
# Descr: CPE-based CVE Fetcher
#   VulnWatcher - Tool in alpha
#   Copyright (C) 2025  Enzo LE NAIR
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU Affero General Public License as
#   published by the Free Software Foundation, either version 3 of the
#   License, or (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU Affero General Public License for more details.
#
#   You should have received a copy of the GNU Affero General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.

import requests
from requests.auth import HTTPBasicAuth
import json
from datetime import datetime, timezone, timedelta
import keyring
from docxtpl import DocxTemplate
import os
import re
import xml.sax.saxutils


def sanitize_text(text):
    if not text:
        return ""
    text = re.sub(r'<[^>]+>', '', text)
    text = xml.sax.saxutils.escape(text)
    return text.strip()

def detect_encoding(file_path):
    with open(file_path, 'rb') as f:
        raw_data = f.read()
    import chardet
    result = chardet.detect(raw_data)
    return result['encoding']


USERNAME = "youruser"
PASSWORD = keyring.get_password("https://www.opencve.io/api", USERNAME)


def enisa(cve_id):
    url = f"https://euvdservices.enisa.europa.eu/api/enisaid?id={cve_id}"
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json",
        "Referer": "https://euvd.enisa.europa.eu/",
        "X-Requested-With": "XMLHttpRequest"
    }

    try:
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            raise Exception(f"HTTP Error: {response.status_code}")
        data = response.json()
    except Exception as e:
        print(f"ENISA fetch failed for {cve_id}: {e}")
        return "N/A", "N/A", "Pas d'informations", "N/A", "N/A", "N/A", "Non"

    euvd_id = data.get("id", {})
    epss = data.get("epss")
    kev = bool(data.get("exploitedSince"))
    presence_kev = "Oui" if kev else "Non"

    references = data.get("references", "Pas d'informations")
    try:
        product_name = data["enisaIdProduct"][0]["product"]["name"]
    except (KeyError, IndexError, TypeError):
        product_name = None

    try:
        vendor_name = data["enisaIdVendor"][0]["vendor"]["name"]
    except (KeyError, IndexError, TypeError):
        vendor_name = None

    try:
        pd = data["enisaIdProduct"][0].get("product_version", "")
        if "unspecified" in pd:
            pd = pd.replace("unspecified", " ")
    except:
        pd = None

    return euvd_id, epss, references, vendor_name, product_name, pd, presence_kev


def getting_CVSS(cvename):
    base_url = f"https://app.opencve.io/api/cve/{cvename}"
    response = requests.get(base_url, auth=HTTPBasicAuth(USERNAME, PASSWORD))
    if response.status_code != 200:
        return "N/A"
    data = response.json()
    return data.get("metrics", {}).get("cvssV3_1", {}).get("data", {}).get("score", "N/A")


def get_cves_from_cpe(cpe, days=30):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "cpeName": cpe,
        "pubStartDate": (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(),
        "pubEndDate": datetime.now(timezone.utc).isoformat()
    }
    headers = {
        "User-Agent": "CPE-CVE-Checker/1.0"
    }

    all_cves = []
    start_index = 0
    while True:
        params["startIndex"] = start_index
        response = requests.get(base_url, params=params, headers=headers)
        if response.status_code != 200:
            print(f"Failed to fetch CVEs for CPE {cpe}: {response.status_code}")
            break

        data = response.json()
        all_cves.extend(data.get("vulnerabilities", []))

        if start_index + len(data.get("vulnerabilities", [])) >= data.get("totalResults", 0):
            break
        start_index += len(data.get("vulnerabilities", []))

    parsed_cves = []
    for entry in all_cves:
        cve_data = entry.get("cve", {})
        parsed_cves.append({
            "cve_id": cve_data.get("id"),
            "description": cve_data.get("descriptions", [{}])[0].get("value", "N/A")
        })

    filename = f"sample_{cpe.replace(':', '_')}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(parsed_cves, f, indent=4)
    print(f"Saved {len(parsed_cves)} CVEs for CPE {cpe} to {filename}")


def analyse_multiple_json(json_dir, template_path="vuln_template.docx", output_path="Report_generated.docx"):
    doc = DocxTemplate(template_path)
    now = datetime.now(timezone.utc)
    last = now - timedelta(days=30)
    all_cves = []

    for filename in os.listdir(json_dir):
        if filename.endswith(".json"):
            file_path = os.path.join(json_dir, filename)
            with open(file_path, "r", encoding="utf-8") as file:
                try:
                    data = json.load(file)
                    if isinstance(data, dict): data = [data]
                    if not isinstance(data, list): continue

                    for item in data:
                        try:
                            euvd, epss, references, vendor, product, pd, kev = enisa(item.get("cve_id", "N/A"))
                        except Exception as e:
                            print(f"ENISA fetch failed: {e}")
                            euvd = epss = references = vendor = product = pd = kev = "N/A"

                        all_cves.append({
                            "cve_id": item.get("cve_id", "N/A"),
                            "description": item.get("description", "N/A"),
                            "cvss": getting_CVSS(item.get("cve_id", "")),
                            "euvd": euvd,
                            "epss": epss,
                            "kev": kev,
                            "references": references,
                            "produit": " ".join(filter(None, [vendor, product, pd])).replace("unspecified", "").strip()
                        })
                except json.JSONDecodeError:
                    print(f"Invalid JSON: {filename}")

    for cve in all_cves:
        for key in cve:
            if isinstance(cve[key], str):
                cve[key] = sanitize_text(cve[key])

    context = {
        "vuln_total": len(all_cves),
        "cves": all_cves,
        "date_debut": last.strftime("%Y-%m-%d %H:%M"),
        "date_fin": now.strftime("%Y-%m-%d %H:%M"),
    }

    doc.render(context)
    doc.save(output_path)
    print(f"Report saved to: {output_path}")

def json_merger():
    path = "."
    merged_data = []
    for file in os.listdir(path):
        if file.endswith(".json"):
            encoding = detect_encoding(file)
            with open(file, 'r', encoding=encoding) as f:
                data = json.load(f)
                if isinstance(data, list):
                    merged_data.extend(data)
                else:
                    merged_data.append(data)
    with open("merged_json.json", 'w', encoding='utf-8') as outfile:
        json.dump(merged_data, outfile)

if __name__ == "__main__":
    cpe_list = [
        "cpe:2.3:o:fortinet:fortios:6.4.2:*:*:*:*:*:*:*",
        "cpe:2.3:a:veeam:veeam_backup_\&_replication:11.0.1.1261:-:*:*:*:*:*:*",
        "cpe:2.3:a:stormshield:stormshield_network_security:4.3.10:*:*:*:*:*:*:*",
        "cpe:2.3:o:redhat:enterprise_linux:7.0:*:*:*:*:*:*:*"
    ]

    for cpe in cpe_list:
        get_cves_from_cpe(cpe)

    analyse_multiple_json(".")
