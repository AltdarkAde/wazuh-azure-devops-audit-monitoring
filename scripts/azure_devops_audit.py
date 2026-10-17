#!/usr/bin/env python3
"""
Azure DevOps Audit Log Collector for Wazuh
Collects audit logs from Azure DevOps and writes them to a JSON file for Wazuh monitoring.
"""

import requests
import json
import os
import sys
from datetime import datetime, timedelta

# Configuration from environment variables
ORGANIZATION = os.environ.get("AZDO_ORG", "")
CLIENT_ID = os.environ.get("AZDO_CLIENT_ID", "")
TENANT_ID = os.environ.get("AZDO_TENANT_ID", "")
CLIENT_SECRET = os.environ.get("AZDO_CLIENT_SECRET", "")
LOG_FILE = "/var/log/AzureDevops/AzureDevops_Audit_logs.json"
API_VERSION = "7.2-preview.1"


def validate_config():
    """Validate that all required configuration is present"""
    missing = []
    if not ORGANIZATION:
        missing.append("AZDO_ORG")
    if not CLIENT_ID:
        missing.append("AZDO_CLIENT_ID")
    if not TENANT_ID:
        missing.append("AZDO_TENANT_ID")
    if not CLIENT_SECRET:
        missing.append("AZDO_CLIENT_SECRET")

    if missing:
        print(f"ERROR: Missing required environment variables: {', '.join(missing)}")
        print("Please ensure these are set in /var/ossec/integrations/azure_devops.env")
        sys.exit(1)

    print("✓ Configuration validated")
    print(f"  Organization: {ORGANIZATION}")
    print(f"  Client ID: {CLIENT_ID[:8]}...{CLIENT_ID[-4:]}")
    print(f"  Tenant ID: {TENANT_ID[:8]}...{TENANT_ID[-4:]}")


def get_access_token():
    """Obtain an access token using client credentials flow. Returns token string or None."""
    print("\n[1/3] Requesting access token from Microsoft Entra ID...")

    token_url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        # Well-known resource ID for Azure DevOps
        "scope": "499b84ac-1321-427f-aa17-267ca6975798/.default",
    }

    try:
        response = requests.post(token_url, headers=headers, data=data, timeout=30)

        if response.status_code == 200:
            print("✓ Access token obtained successfully")
            return response.json().get("access_token")

        print("✗ Failed to obtain access token")
        print(f"  Status Code: {response.status_code}")
        print(f"  Response: {response.text}")
        return None

    except requests.exceptions.RequestException as e:
        print(f"✗ Network error while obtaining token: {str(e)}")
        return None
    except Exception as e:
        print(f"✗ Unexpected error while obtaining token: {str(e)}")
        return None


def fetch_audit_logs(access_token):
    """Fetch audit logs from Azure DevOps. Returns a list of entries or None on failure."""
    print("\n[2/3] Fetching audit logs from Azure DevOps...")

    # Time range: last 5 minutes
    end_time = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    start_time = (datetime.utcnow() - timedelta(minutes=5)).replace(microsecond=0).isoformat() + "Z"
    print(f"  Time range: {start_time} to {end_time}")

    audit_url = (
        f"https://auditservice.dev.azure.com/{ORGANIZATION}/_apis/audit/downloadlog"
        f"?format=json&startTime={start_time}&endTime={end_time}&api-version={API_VERSION}"
    )
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    try:
        response = requests.get(audit_url, headers=headers, timeout=60)

        if response.status_code == 200:
            logs = response.json()
            if isinstance(logs, list):
                print(f"✓ Successfully retrieved {len(logs)} audit log entries")
                return logs
            print(f"✓ Retrieved audit logs (format: {type(logs).__name__})")
            return logs if logs else []

        if response.status_code == 401:
            print("✗ Authentication failed (401 Unauthorized)")
            print("  This usually means:")
            print("    - The service principal doesn't have audit log permissions")
            print("    - The service principal hasn't been added to Azure DevOps")
            print("    - Auditing is not enabled in Azure DevOps")
            return None

        if response.status_code == 403:
            print("✗ Access forbidden (403 Forbidden)")
            print("  The service principal needs to be added to the Azure DevOps organization")
            return None

        print("✗ Failed to fetch audit logs")
        print(f"  Status Code: {response.status_code}")
        print(f"  Response: {response.text[:500]}")
        return None

    except requests.exceptions.RequestException as e:
        print(f"✗ Network error while fetching logs: {str(e)}")
        return None
    except Exception as e:
        print(f"✗ Unexpected error while fetching logs: {str(e)}")
        return None


def write_logs_to_file(logs):
    """Write enriched logs to a JSON-lines file for Wazuh ingestion."""
    print(f"\n[3/3] Writing logs to {LOG_FILE}...")

    if not logs:
        print("  No logs to write")
        return True

    try:
        log_dir = os.path.dirname(LOG_FILE)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir, mode=0o750)
            print(f"  Created log directory: {log_dir}")

        written_count = 0
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            for log in logs:
                enriched_log = {"Logtype": "AzureDevops"}
                for key, value in log.items():
                    enriched_log[f"AzureDevops.{key}"] = value
                f.write(json.dumps(enriched_log, ensure_ascii=False) + "\n")
                written_count += 1

        print(f"✓ Successfully wrote {written_count} log entries to file")
        return True

    except PermissionError:
        print(f"✗ Permission denied writing to {LOG_FILE}")
        print("  Ensure the script has write permissions to this location")
        return False
    except Exception as e:
        print(f"✗ Error writing logs to file: {str(e)}")
        return False


def main():
    print("=" * 70)
    print("Azure DevOps Audit Log Collector for Wazuh")
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    validate_config()

    access_token = get_access_token()
    if not access_token:
        print("\n" + "=" * 70)
        print("FAILED: Could not obtain access token")
        print("=" * 70)
        sys.exit(1)

    logs = fetch_audit_logs(access_token)
    if logs is None:
        print("\n" + "=" * 70)
        print("FAILED: Could not fetch audit logs")
        print("=" * 70)
        sys.exit(1)

    success = write_logs_to_file(logs)

    print("\n" + "=" * 70)
    print("SUCCESS: Audit log collection completed" if success else "FAILED: Error writing logs to file")
    print(f"Finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
