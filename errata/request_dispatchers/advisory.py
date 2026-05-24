from concurrent.futures import ThreadPoolExecutor, as_completed
from lib.errata.errata_requests import get_advisory_data


def validate_advisory_get(request):

    """
    This function validates whether the received request is valid or not.
    If not valid return is False with suitable response.
    If the request is valid return is True with parameters for next function call.
    :param request:
    :return:
    """

    # all the valid request types for the url
    valid_request_types = ["advisory"]

    # url parameters, assuming they are compulsory for now
    request_type = request.query_params.get("type", None)
    advisory_id = request.query_params.get("id", None)

    # if compulsory parameters missing return False for validation and suitable response
    if not request_type or not advisory_id:
        return False, {"status": "error", "message": "Missing query params.", "data": []}

    # if the request type received from url parameters is not in valid request types
    if request_type not in valid_request_types:
        return False, {"status": "error", "message": "Invalid value for parameter \"type\".", "data": []}

    if request_type == "advisory":
        # if request type is advisory and id can't be empty, checked earlier then return true
        return True, {"type": request_type, "id": advisory_id}

    return False, {"status": "error", "message": "URL validation failed.", "data": []}


def route_advisory_get(request_param):

    """
    This method routes the request type to respective methods.
    :param request_param: Parameters for the request. Used to route requests and pass the data
    to the respective functions.
    :return: Dict, final response to the view.
    """

    if request_param["type"] == "advisory":
        data = get_advisory_data(request_param["id"])
        if isinstance(data, dict) and "error" in data:
            return {"status": "error", "message": data["message"], "data": None}
        return {"status": "success", "message": "Data is ready.", "data": data}


def validate_batch_advisory_get(request):
    ids_param = request.query_params.get("ids", None)
    if not ids_param:
        return False, {"status": "error", "message": "Missing 'ids' query param.", "data": []}

    advisory_ids = [aid.strip() for aid in ids_param.split(",") if aid.strip()]
    if not advisory_ids:
        return False, {"status": "error", "message": "No valid advisory IDs provided.", "data": []}

    return True, {"ids": advisory_ids}


def route_batch_advisory_get(request_param):
    advisory_ids = request_param["ids"]
    results = {}

    with ThreadPoolExecutor(max_workers=min(len(advisory_ids), 8)) as pool:
        futures = {pool.submit(get_advisory_data, aid): aid for aid in advisory_ids}
        for future in as_completed(futures):
            aid = futures[future]
            data = future.result()
            if isinstance(data, dict) and "error" in data:
                results[aid] = {"status": "error", "message": data["message"], "data": None}
            else:
                results[aid] = {"status": "success", "message": "Data is ready.", "data": data}

    return {"status": "success", "message": "Batch data is ready.", "data": results}
