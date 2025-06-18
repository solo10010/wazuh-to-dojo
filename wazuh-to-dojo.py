import requests
import json
import logging
import os
import argparse
from datetime import datetime

# Logging configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

class WazuhToDefectDojoJSONExporter:
    def __init__(self,
                 indexer_url="https://<REDACTED-IP>:9200",
                 username="user",
                 password="********",
                 dojo_url="http://<REDACTED-IP>:8080/",
                 api_key="********",
                 product_id=3,
                 engagement_id=9,
                 test_id=None):
        self.indexer_url = indexer_url
        self.auth = (username, password)
        self.headers = {"Content-Type": "application/json"}
        self.dojo_url = dojo_url.rstrip("/")
        self.api_key = api_key
        self.product_id = product_id
        self.engagement_id = engagement_id
        self.test_id = test_id
        requests.packages.urllib3.disable_warnings()
        logger.info("Wazuh to DefectDojo JSON exporter initialized")

    def get_agent_info(self, agent_id):
        query = {
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"id": agent_id}}
                    ]
                }
            },
            "size": 1
        }
        try:
            url = f"{self.indexer_url}/wazuh-states-agents-*/_search"
            response = requests.get(url, headers=self.headers, auth=self.auth,
                                    verify=False, data=json.dumps(query))
            response.raise_for_status()
            hits = response.json().get("hits", {}).get("hits", [])
            if hits:
                source = hits[0]["_source"]
                return {
                    "ip": source.get("ip", "unknown"),
                    "groups": source.get("group", ["unknown"])
                }
        except Exception as e:
            logger.error(f"Failed to get agent info {agent_id}: {e}")
        return {"ip": "unknown", "groups": ["unknown"]}

    def get_all_vulnerabilities(self):
        url = f"{self.indexer_url}/wazuh-states-vulnerabilities-*/_search?scroll=1m"
        query = {
            "query": {"match_all": {}},
            "size": 1000
        }
        try:
            response = requests.get(url, headers=self.headers, auth=self.auth,
                                    verify=False, data=json.dumps(query))
            response.raise_for_status()
            data = response.json()
            scroll_id = data.get("_scroll_id")
            hits = [h["_source"] for h in data.get("hits", {}).get("hits", [])]
            vulnerabilities = hits.copy()

            while hits:
                scroll_query = {"scroll": "1m", "scroll_id": scroll_id}
                response = requests.get(f"{self.indexer_url}/_search/scroll",
                                        headers=self.headers, auth=self.auth,
                                        verify=False, data=json.dumps(scroll_query))
                response.raise_for_status()
                data = response.json()
                scroll_id = data.get("_scroll_id")
                hits = [h["_source"] for h in data.get("hits", {}).get("hits", [])]
                vulnerabilities.extend(hits)

            return vulnerabilities
        except Exception as e:
            logger.error(f"Failed to get vulnerabilities: {e}")
            return []

    def build_json(self, vulns):
        allowed_severities = ["Info", "Low", "Medium", "High", "Critical"]
        items = []

        for v in vulns:
            agent_id = v.get("agent", {}).get("id", "unknown")
            agent_name = v.get("agent", {}).get("name", "")
            agent_info = self.get_agent_info(agent_id)
            ip = agent_info.get("ip", "")

            vuln_data = v.get("vulnerability", {})
            package = v.get("package", {})

            raw_severity = str(vuln_data.get("severity", "")).strip().capitalize()
            severity = raw_severity if raw_severity in allowed_severities else "Info"

            refs = vuln_data.get("reference", [])
            if refs is None:
                refs = []
            elif isinstance(refs, str):
                refs = [refs]
            references = "\n".join(refs)

            description = vuln_data.get("description", "No description provided.")
            mitigation = vuln_data.get("status", "")
            impact = vuln_data.get("condition", "")

            endpoints = []
            if ip and ip != "unknown":
                endpoints.append({"host": ip})
            if agent_name and agent_name != "unknown":
                endpoints.append({"host": agent_name})

            item = {
                "title": f"{vuln_data.get('id', 'CVE')} affects {package.get('name', 'unknown')}",
                "date": vuln_data.get("published_at", "")[:10] or datetime.now().strftime("%Y-%m-%d"),
                "cve": vuln_data.get("id", "unknown"),
                "severity": severity,
                "description": description,
                "mitigation": mitigation,
                "impact": impact,
                "references": references,
                "component_name": package.get("name", "unknown"),
                "component_version": package.get("version", "unknown"),
                "static_finding": True,
                "dynamic_finding": False,
                "endpoints": endpoints
            }

            items.append(item)

        return {"findings": items}

    def upload_to_defectdojo(self, json_path):
        logger.info("Uploading to DefectDojo...")

        scan_url = f"{self.dojo_url}/api/v2/"
        scan_url += "reimport-scan/" if self.test_id else "import-scan/"

        headers = {
            "Authorization": f"Token {self.api_key}"
        }
        files = {
            "file": (os.path.basename(json_path), open(json_path, "rb"), "application/json")
        }
        data = {
            "scan_type": "Generic Findings Import",
            "scan_title": "Wazuh Vulnerability Export",
            "scan_date": datetime.now().strftime("%Y-%m-%d"),
            "active": "true",
            "verified": "true",
            "close_old_findings": "false",
            "skip_duplicates": "true",
            "minimum_severity": "Info",
            "tags": "wazuh"
        }

        if self.test_id:
            data["test"] = str(self.test_id)
        else:
            data["product"] = str(self.product_id)
            data["engagement"] = str(self.engagement_id)

        response = requests.post(scan_url, headers=headers, files=files, data=data, verify=False)
        files["file"][1].close()

        if response.status_code in (200, 201):
            logger.info("[✅] Successfully uploaded to DefectDojo.")
        else:
            logger.error(f"[❌] Upload failed: {response.status_code} — {response.text}")

    def run_export(self, destination_file="wazuh_defectdojo.json"):
        logger.info("Retrieving vulnerabilities from Wazuh...")
        vulnerabilities = self.get_all_vulnerabilities()
        logger.info(f"Total vulnerabilities retrieved: {len(vulnerabilities)}")

        if not vulnerabilities:
            logger.warning("No vulnerabilities to export.")
            return

        json_data = self.build_json(vulnerabilities)

        with open(destination_file, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False)

        logger.info(f"[💾] JSON file created: {destination_file}")

        self.upload_to_defectdojo(destination_file)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Export Wazuh vulnerabilities to DefectDojo")
    parser.add_argument("--rescan", type=int, help="DefectDojo test ID for reimport-scan")
    args = parser.parse_args()

    exporter = WazuhToDefectDojoJSONExporter(test_id=args.rescan)
    exporter.run_export()

