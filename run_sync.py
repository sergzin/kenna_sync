import gzip
import os
import tempfile
from pathlib import Path

import requests

from kenna import KennaDataImporter, KennaAsset, KennaVulnDef, KennaDataExportModel, KennaDataExportAssets, \
    KennaDataExportVulns, Vulnerability, Findings
from request_download import request_download

DESTINATION_KENNA_API_KEY = os.environ['DESTINATION_KENNA_API_KEY']
DESTINATION_KENNA_API_URL = os.environ['DESTINATION_KENNA_API_URL']
DESTINATION_KENNA_CONNECTOR_ID = int(os.environ['DESTINATION_KENNA_CONNECTOR_ID'])


def load_file(filename: Path):
    data = gzip.decompress(filename.read_bytes())
    model = KennaDataExportModel.model_validate_json(data)
    return model


def search_files(directory: Path):
    for p in directory.glob('search_id_*.gz'):
        print(f"Reading {p}")
        model = load_file(p)
        yield model


def search_vulns(asset_id: int, source):
    for item in source:
        if item['asset_id'] == asset_id:
            kenna_vuln_id = f"SourceID_{item['id']}"
            cve_id = item['cve_id']
            kenna_vuln = Vulnerability(
                scanner_identifier=kenna_vuln_id,
                scanner_type="KennaDataImporter",
                scanner_score=item.get('scanner_score'),
                created_at=item.get('created_at'),
                last_seen_at=item.get('last_seen_time'),
                last_fixed_on=item.get('closed_at'),
                status="open" if "open" in item["status"] else "closed",
                details=item.get('details'),
                port=item['port'][0] if item.get('port') else None,
                vuln_def_name=cve_id
            )
            vuln_def = KennaVulnDef(
                scanner_type="KennaDataImporter",
                cve_identifiers=item.get('cve_id'),
                name=cve_id,
                description=item.get('description') or item.get('cve_description'),
                solution=item.get('solution'),
            )
            finding = Findings(
                scanner_type="KennaDataImporter",
                scanner_identifier=kenna_vuln_id,
                created_at=item.get('created_at'),
                due_date=item.get('due_date'),
                last_seen_at=item.get('last_seen_time'),
                severity=item.get('severity'),
                # triage_state = item.get('triage_state'),
                # additional_fields = {"identifiers": item.get('identifiers'),
                #                      "scanner_vulnerabilities": item.get('scanner_vulnerabilities')},
                vuln_def_name=cve_id
            )
            yield kenna_vuln, vuln_def, finding


def sync_kenna(source_dir: Path):
    kenna_data = KennaDataImporter()
    assets = []
    vulns = []
    seen_vuln_def = []
    for model in search_files(source_dir):
        if isinstance(model.root, KennaDataExportAssets):
            assets = model.root.assets
        if isinstance(model.root, KennaDataExportVulns):
            vulns = model.root.vulnerabilities
    print(f"Got {len(assets)} assets and {len(vulns)} vulnerabilities")
    for item in assets:
        asset_id = item['id']
        kenna_asset = KennaAsset(
            file=item.get('file'),
            ip_address=item.get('ip_address'),
            hostname=item.get('hostname'),
            netbios=item.get('netbios'),
            url=item.get('url'),
            fqdn=item.get('fqdn'),
            external_id=item.get('external_id'),
            database=item.get('database'),
            tags=item.get('tags'),
            owner=item.get('owner'),
            os=item.get('os'),
            os_version=item.get('os_version'),
            priority=item.get('priority'),
            last_seen_at=item.get('last_seen_time'),

        )
        for vuln, vuln_def, finding in search_vulns(asset_id, vulns):
            kenna_asset.vulns.append(vuln)
            kenna_asset.findings.append(finding)
            if vuln_def.name not in seen_vuln_def:
                seen_vuln_def.append(vuln_def.name)
                kenna_data.vuln_defs.append(vuln_def)
        kenna_data.assets.append(kenna_asset)
    # print(kenna_data.model_dump_json(indent=2, exclude_none=True))
    # with open("output.json", "w") as f:
    #     f.write(kenna_data.model_dump_json(indent=2, exclude_none=True))
    print(f"Uploading {len(kenna_data.assets)} assets to Kenna API")
    upload_kdi_to_kenna(kenna_data, DESTINATION_KENNA_API_URL, DESTINATION_KENNA_API_KEY,
                        DESTINATION_KENNA_CONNECTOR_ID)
    print("Done")


def upload_kdi_to_kenna(data: KennaDataImporter, kenna_api_url, kenna_api_key, connector_id):
    session = requests.Session()
    session.headers.update({"X-Risk-Token": kenna_api_key})
    form_data = {'file': ('kenna_data.json', data.model_dump_json(exclude_none=True)),
                 'run': (None, 'true')}
    with session.post(f"{kenna_api_url}/connectors/{connector_id}/data_file", files=form_data) as response:
        if not response.ok:
            print(response.text)
            response.raise_for_status()


if __name__ == '__main__':
    with tempfile.TemporaryDirectory() as temp_dir:
        path = Path(temp_dir)
        request_download(path)
        sync_kenna(path)
