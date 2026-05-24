import os
import requests
import logging
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from requests_gssapi import HTTPSPNEGOAuth
from .decorators import update_keytab

logger = logging.getLogger(__name__)

HTTP_TIMEOUT = (5, 30)


def _errata_get(url):
    """Shared helper for authenticated GET with timeout."""
    return requests.get(
        urlparse(url).geturl(),
        verify=ssl.get_default_verify_paths().openssl_cafile,
        auth=HTTPSPNEGOAuth(),
        timeout=HTTP_TIMEOUT,
    )


@update_keytab
def get_advisory_data(advisory_id):
    """
    This method returns advisory data for a given id.
    :param advisory_id: The id of the advisory to get data for.
    :return: Dict with advisory data, or dict with 'error' key on failure.
    """

    try:
        errata_url = os.environ["ERRATA_ADVISORY_ENDPOINT"].format(advisory_id)
        jira_url = f"{os.environ['ERRATA_SERVER']}/advisory/{advisory_id}/jira_issues.json"

        with ThreadPoolExecutor(max_workers=2) as pool:
            future_advisory = pool.submit(_errata_get, errata_url)
            future_jira = pool.submit(_errata_get, jira_url)

            response = future_advisory.result()
            jira_response = future_jira.result()

        if response.status_code != 200:
            logger.warning("Errata API returned %s for advisory %s", response.status_code, advisory_id)
            return {
                "error": "errata_api_error",
                "message": f"Errata API returned HTTP {response.status_code}",
                "advisory_id": advisory_id,
            }

        advisory_data = response.json()

        jira_issues_data = None
        if jira_response.status_code == 200:
            jira_issues_data = jira_response.json()
        else:
            logger.warning("Jira issues endpoint returned %s for advisory %s", jira_response.status_code, advisory_id)

        return format_advisory_data(advisory_data, jira_issues_data)

    except requests.exceptions.Timeout:
        logger.exception("Timeout fetching advisory %s", advisory_id)
        return {
            "error": "timeout",
            "message": "Errata request timed out",
            "advisory_id": advisory_id,
        }
    except requests.exceptions.ConnectionError:
        logger.exception("Connection error fetching advisory %s", advisory_id)
        return {
            "error": "connection_error",
            "message": "Could not connect to Errata server",
            "advisory_id": advisory_id,
        }
    except Exception:
        logger.exception("Unexpected error fetching advisory %s", advisory_id)
        return {
            "error": "unknown",
            "message": "An unexpected error occurred while fetching advisory data",
            "advisory_id": advisory_id,
        }


def get_user_data(user_id):
    """
    This method returns user data for a given id.
    Called from within get_advisory_data which already holds a valid Kerberos ticket.
    :param user_id: The id of the user to get data for.
    :return: Dict, user data.
    """

    try:
        errata_endpoint = os.environ["ERRATA_USER_ENDPOINT"]
        response = _errata_get(errata_endpoint.format(user_id))
        return format_user_data(response.json())
    except Exception:
        logger.exception("Error fetching user data for user %s", user_id)
        return None


def format_user_data(user_data):
    return user_data


def format_advisory_data(advisory_data, jira_issues_data):
    """
    This method filters the data for an advisory from errata to pick required content.
    :param advisory_data: The advisory data received from errata.
    :return: Dictionary of filtered response.
    """

    advisory_details = []
    final_response = {}

    if "errata" in advisory_data:
        errata_data = advisory_data["errata"]
        for key in errata_data:

            advisory_detail = dict()
            advisory_detail["advisory_type"] = key

            if "id" in errata_data[key]:
                advisory_detail["id"] = errata_data[key]["id"]
            else:
                advisory_detail["id"] = None

            if "release_date" in errata_data[key]:
                if errata_data[key]["release_date"] is None:
                    advisory_detail["release_date"] = "Unassigned"
                else:
                    advisory_detail["release_date"] = errata_data[key]["release_date"]
            else:
                advisory_detail["release_date"] = "Unassigned"

            if "publish_date" in errata_data[key]:
                if errata_data[key]["publish_date"] is None:
                    advisory_detail["publish_date"] = "Unassigned"
                else:
                    advisory_detail["publish_date"] = errata_data[key]["publish_date"].split("T")[0]
            else:
                advisory_detail["publish_date"] = "Unassigned"

            if "synopsis" in errata_data[key]:
                advisory_detail["synopsis"] = errata_data[key]["synopsis"]
            else:
                advisory_detail["synopsis"] = "Not Described"

            if "qa_complete" in errata_data[key]:
                if errata_data[key]["qa_complete"] == 0:
                    advisory_detail["qa_complete"] = "Requested"
                elif errata_data[key]["qa_complete"] == 1:
                    advisory_detail["qa_complete"] = "Complete"
                else:
                    advisory_detail["qa_complete"] = "Not Requested"
            else:
                advisory_detail["qa_complete"] = "Unknown"

            if "status" in errata_data[key]:
                advisory_detail["status"] = errata_data[key]["status"]
            else:
                advisory_detail["status"] = "Unknown"

            if "doc_complete" in errata_data[key]:
                if errata_data[key]["doc_complete"] == 1:
                    advisory_detail["doc_complete"] = "Approved"
                elif errata_data[key]["doc_complete"] == 0:
                    advisory_detail["doc_complete"] = "Requested"
                else:
                    advisory_detail["doc_complete"] = "Not Requested"

            else:
                advisory_detail["doc_complete"] = "Unknown"

            if "security_approved" in errata_data[key]:
                if errata_data[key]["security_approved"] == 1:
                    advisory_detail["security_approved"] = "Approved"
                elif errata_data[key]["security_approved"] == 0:
                    advisory_detail["security_approved"] = "Requested"
                else:
                    advisory_detail["security_approved"] = "Not Requested"
            else:
                advisory_detail["security_approved"] = "Unknown"

            if "content" in advisory_data and "content" in advisory_data["content"]:
                content = advisory_data["content"]["content"]
                qe_reviewer_id = None
                doc_reviewer_id = content.get("doc_reviewer_id")
                product_security_reviewer_id = content.get("product_security_reviewer_id")

                reviewer_ids = {
                    "qe_reviewer": qe_reviewer_id,
                    "doc_reviewer": doc_reviewer_id,
                    "product_security_reviewer": product_security_reviewer_id,
                }
                reviewer_details = {k: None for k in reviewer_ids}

                ids_to_fetch = {k: v for k, v in reviewer_ids.items() if v is not None}
                if ids_to_fetch:
                    with ThreadPoolExecutor(max_workers=len(ids_to_fetch)) as pool:
                        futures = {pool.submit(get_user_data, uid): role for role, uid in ids_to_fetch.items()}
                        for future in as_completed(futures):
                            reviewer_details[futures[future]] = future.result()

                for role, uid in reviewer_ids.items():
                    advisory_detail[f"{role}_id"] = uid
                    advisory_detail[f"{role}_details"] = reviewer_details[role]

            advisory_details.append(advisory_detail)

    final_response["advisory_details"] = advisory_details

    total_bugs = 0
    jira_bugs_details = []
    total_jira_bugs = 0
    jira_bug_summary = dict()
    bugzilla_bugs_details = []
    total_bugzilla_bugs = 0
    bugzilla_bug_summary = dict()

    if jira_issues_data:
        for jira_issue in jira_issues_data:
            jira_bug_detail = {
                "id_jira": jira_issue.get("id_jira"),
                "key": jira_issue.get("key"),
                "summary": jira_issue.get("summary"),
                "status": jira_issue.get("status"),
                "is_private": jira_issue.get("is_private"),
                "labels": jira_issue.get("labels"),
            }
            jira_bugs_details.append(jira_bug_detail)
            total_jira_bugs += 1

            if jira_bug_detail["status"] not in jira_bug_summary:
                jira_bug_summary[jira_bug_detail["status"]] = 0
            jira_bug_summary[jira_bug_detail["status"]] += 1

    if "bugs" in advisory_data:
        bugzilla_data = advisory_data["bugs"]

        if "bugs" in advisory_data:
            bugzilla_data = advisory_data["bugs"]

            bug_data = bugzilla_data["bugs"]

            for each_bug in bug_data:
                each_bug = each_bug["bug"]
                bug = dict()
                bug["id"] = each_bug["id"]
                bug["bug_status"] = each_bug["bug_status"]
                bug["bug_link"] = "https://bugzilla.redhat.com/show_bug.cgi?id=" + str(each_bug["id"])
                bugzilla_bugs_details.append(bug)

                if bug["bug_status"] not in bugzilla_bug_summary:
                    bugzilla_bug_summary[bug["bug_status"]] = 0

                bugzilla_bug_summary[bug["bug_status"]] += 1
                total_bugzilla_bugs += 1

    final_response["bugs"] = bugzilla_bugs_details
    bug_summary_array = []
    for key in jira_bug_summary:
        if total_jira_bugs == 0:
            bug_summary_array.append({
                "bug_status": key,
                "count": jira_bug_summary[key],
            })
        else:
            bug_summary_array.append({
                "bug_status": key,
                "count": jira_bug_summary[key],
            })

    for key in bugzilla_bug_summary:
        if total_bugs == 0:
            bug_summary_array.append({
                "bug_status": key,
                "count": bugzilla_bug_summary[key],
            })
        else:
            bug_summary_array.append({
                "bug_status": key,
                "count": bugzilla_bug_summary[key],
            })

    final_response["bug_summary"] = bug_summary_array

    return final_response
