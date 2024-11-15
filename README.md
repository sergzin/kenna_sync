# Kenna Sync

Copy assets and vulnerabilities from one Kenna instance to another.

This script will download Assets and Vulnerabilities using kenna data export API and will upload data to another Kenna instance using Kenna Data Import API. 
It is not possible to export findings and fixes using Risk Meter ID.

## requirements

requests==2.32.3
pydantic==2.9.2

## running script

`python run_sync.py`

## environment variables

* `DESTINATION_KENNA_API_KEY` - Destination Kenna API key (where data should be uploaded)
* `DESTINATION_KENNA_API_URL` - Destination Kenna API URL
* `DESTINATION_KENNA_CONNECTOR_ID` - ID of "Data Importer" connector 
* `SOURCE_KENNA_API_KEY` - Source Kenna API key (Where data will be exported)
* `SOURCE_KENNA_API_URL` - Source Kenna API URL
* `SOURCE_KENNA_RISK_METER_ID` - ID of Risk Meter specifying which assets will be exported. In documentation it is called [search_id](https://apidocs.kennasecurity.com/reference/request-data-export) 

## Links

* [Data Importer](https://help.kennasecurity.com/hc/en-us/articles/360026413111-Data-Importer-JSON-Connector)
* [Data Export Specs](https://apidocs.kennasecurity.com/reference/retrieve-data-export)