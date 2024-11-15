import os
import time
from pathlib import Path

import requests

KENNA_API_URL = os.environ['SOURCE_KENNA_API_URL']
api_key = os.environ['SOURCE_KENNA_API_KEY']
headers = {
    "accept": "application/json",
    "content-type": "application/json",
    'X-Risk-Token': api_key,
}
KENNA_RISK_METER_ID = int(os.environ['SOURCE_KENNA_RISK_METER_ID']) # ID of Kenna Risk Meter (search ID)


def request_asset_data_export(risk_meter_id: int):
    url = f"{KENNA_API_URL}/data_exports"
    payload = {
        "export_settings": {
            "format": "json",
            "model": "asset",
            "slim": False,
        },
        "search_id": risk_meter_id,
    }
    response = requests.post(url, json=payload, headers=headers)
    if response.status_code != 200:
        print(response.text)
        response.raise_for_status()
    return response.json()['search_id']


def request_vulnerability_data_export(risk_meter_id: int):
    url = f"{KENNA_API_URL}/data_exports"
    payload = {
        "export_settings": {
            "format": "json",
            "model": "vulnerability",
            "slim": False,
        },
        "search_id": risk_meter_id,
    }
    response = requests.post(url, json=payload, headers=headers)
    if response.status_code != 200:
        print(response.text)
        response.raise_for_status()
    return response.json()['search_id']


# def request_finding_data_export(risk_meter_id: int):
#     url = f"{KENNA_API_URL}/data_exports"
#     payload = {
#         "export_settings": {
#             "format": "json",
#             "model": "finding",
#             "slim": False,
#         },
#         "search_id": risk_meter_id,
#     }
#     response = requests.post(url, json=payload, headers=headers)
#     if response.status_code != 200:
#         print(response.text)
#         response.raise_for_status()
#     return response.json()['search_id']


def is_ready_for_download(search_id: int):
    url = f"{KENNA_API_URL}/data_exports/status"
    params = {"search_id": search_id}
    response = requests.get(url, params=params, headers=headers)
    if response.status_code == 200:
        return True
    elif response.status_code == 206:
        return False
    else:
        response.raise_for_status()


def download_data_export(search_id: int, directory: Path):
    url = f"{KENNA_API_URL}/data_exports"
    params = {"search_id": search_id}
    headers.update({"accept": "application/gzip; charset=utf-8"})
    response = requests.get(url, params=params, headers=headers, stream=True)
    output_file = directory / f"search_id_{search_id}.gz"
    if response.status_code == 200:
        print(f"Saving output to {output_file}")
        with open(output_file, "wb") as f:
            for block in response.iter_content(1024):
                f.write(block)
    else:
        response.raise_for_status()


def request_download(tempdir: Path):
    print(f"Requesting assets download")
    asset_search_id = request_asset_data_export(KENNA_RISK_METER_ID)
    vulnerability_search_id = request_vulnerability_data_export(KENNA_RISK_METER_ID)
    # finding_search_id = request_finding_data_export(KENNA_RISK_METER_ID)
    searches = (asset_search_id, vulnerability_search_id,)
    while True:
        print("Check if all searches are ready for download")
        conditions = list(map(is_ready_for_download, searches))
        print(f"Ready?: {conditions}")
        if all(conditions):
            for item in searches:
                download_data_export(item, tempdir)
            break  # while true
        else:
            time.sleep(10)


if __name__ == "__main__":
    request_download(Path(__file__).parent.absolute())
