import os
import re
import yaml
import base64
import hashlib
import logging
import requests
from urllib.parse import quote_plus
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

GITLAB_API_URL = "https://gitlab.cee.redhat.com/api/v4"


def _get_gitlab_headers():
    token = os.environ.get("GITLAB_API_TOKEN", "")
    return {"PRIVATE-TOKEN": token}


def _parse_mr_url(mr_url):
    """Parse a GitLab MR URL into project path and MR IID."""
    match = re.match(r'https?://[^/]+/(.+?)/-/merge_requests/(\d+)', mr_url)
    if not match:
        return None, None
    return match.group(1), int(match.group(2))


def _gitlab_get(endpoint):
    url = f"{GITLAB_API_URL}/{endpoint}"
    response = requests.get(url, headers=_get_gitlab_headers(), timeout=30)
    response.raise_for_status()
    return response.json()


def _get_mr_metadata(project_encoded, iid):
    return _gitlab_get(f"projects/{project_encoded}/merge_requests/{iid}")


def _get_mr_approval_state(project_encoded, iid):
    return _gitlab_get(f"projects/{project_encoded}/merge_requests/{iid}/approval_state")


def _get_file_content(project_encoded, file_path_encoded, ref):
    data = _gitlab_get(f"projects/{project_encoded}/repository/files/{file_path_encoded}?ref={ref}")
    content = base64.b64decode(data["content"]).decode("utf-8")
    return yaml.safe_load(content)


def _parse_shipment_file(parsed_yaml):
    """Extract advisory data from a parsed shipment YAML file."""
    shipment = parsed_yaml.get("shipment", {})
    release_notes = shipment.get("data", {}).get("releaseNotes", {})
    environments = shipment.get("environments", {})

    stage_advisory = environments.get("stage", {}).get("advisory", {})
    prod_advisory = environments.get("prod", {}).get("advisory", {})

    return {
        "type": release_notes.get("type"),
        "live_id": release_notes.get("live_id"),
        "synopsis": release_notes.get("synopsis", ""),
        "stage_url": stage_advisory.get("url"),
        "prod_url": prod_advisory.get("url"),
    }


def _determine_status(labels):
    if "prod-release-success" in labels:
        return "SHIPPED_LIVE"
    elif "stage-release-success" in labels:
        return "Staged"
    return "Pending"


def get_shipment_status(mr_url, branch, assembly):
    """
    Get shipment advisory status from a GitLab MR.

    Returns dict with status, approvals, and per-kind advisory data.
    """
    project_path, iid = _parse_mr_url(mr_url)
    if not project_path or not iid:
        return {"error": f"Could not parse MR URL: {mr_url}"}

    project_encoded = quote_plus(project_path)

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            future_mr = pool.submit(_get_mr_metadata, project_encoded, iid)
            future_approvals = pool.submit(_get_mr_approval_state, project_encoded, iid)

            mr_data = future_mr.result()
            approval_data = future_approvals.result()
    except Exception as e:
        logger.error(f"Error fetching MR metadata for {mr_url}: {e}")
        return {"error": str(e)}

    labels = mr_data.get("labels", [])
    source_branch = mr_data.get("source_branch", "")
    state = mr_data.get("state", "")

    status = _determine_status(labels)

    approvals = {}
    for rule in approval_data.get("rules", []):
        rule_name = rule.get("name", "")
        approved_by_list = rule.get("approved_by", [])
        approver_name = approved_by_list[0].get("name", "") if approved_by_list else ""
        approvals[rule_name] = {
            "approved": rule.get("approved", False),
            "approved_by": approver_name,
        }

    ref = "main" if state == "merged" else source_branch
    timestamp_match = re.match(r'prepare-shipment-.+-(\d+)$', source_branch)
    if not timestamp_match:
        return {
            "status": status,
            "mr_url": mr_url,
            "approvals": approvals,
            "advisories": {},
        }
    timestamp = timestamp_match.group(1)

    app = branch.replace(".", "-")
    kinds = ["image", "extras", "metadata"]

    def fetch_kind(kind):
        file_path = f"shipment/ocp/{branch}/{app}/prod/{assembly}.{kind}.{timestamp}.yaml"
        file_path_encoded = quote_plus(file_path)
        try:
            parsed = _get_file_content(project_encoded, file_path_encoded, ref)
            result = _parse_shipment_file(parsed)
            anchor = hashlib.sha1(file_path.encode()).hexdigest()
            result["diff_url"] = f"{mr_url}/diffs#{anchor}"
            return kind, result
        except Exception as e:
            logger.warning(f"Could not read shipment file for {kind}: {e}")
            return kind, None

    advisories = {}
    try:
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = [pool.submit(fetch_kind, k) for k in kinds]
            for future in as_completed(futures):
                kind, data = future.result()
                if data:
                    advisories[kind] = data
    except Exception as e:
        logger.error(f"Error fetching shipment files: {e}")

    return {
        "status": status,
        "mr_url": mr_url,
        "approvals": approvals,
        "advisories": advisories,
    }
