from typing import List, Optional, Literal, Dict, Any

from pydantic import BaseModel, Field, RootModel


class KennaVulnDef(BaseModel):
    """
    Model for vulnerability definitions
    """
    scanner_type: str
    cve_identifiers: Optional[str] = Field(None,
                                           description="Comma delimited list with format CVE-000-0000. "
                                                       "Only one set of identifiers will be saved per vuln_def.",
                                           pattern=r'^CVE-\d+-\d+')  # Kenna support case #151723
    wasc_identifiers: Optional[str] = None
    cwe_identifiers: Optional[str] = Field(None, description="Comma delimited list with format CWE-000."
                                                             " Only one set of identifiers will be saved per vuln_def. ",
                                           pattern=r'^CWE-\d+')
    name: str
    description: Optional[str] = None
    solution: Optional[str] = None


class Vulnerability(BaseModel):
    """
    Model for CloudSecVulnerability of an asset
    """
    scanner_identifier: str = Field(..., description="Uniquely identifies data coming from a scanner.")
    scanner_type: str = Field(...,
                              description="Identifies the scanner the data came from. Paired with scanner_identifier (see above). ")
    scanner_score: int = Field(..., ge=0, le=10, description="Score given by the scanner. [0..10]")
    override_score: Optional[int] = Field(None, ge=0, le=100,
                                          description="The risk score [0..100] for an informational vulnerability.")
    created_at: Optional[str] = Field(None,
                                      description="ISO8601 timestamp indicating when the vulnerability was first found by the scanner. Defaults to current date if not provided.")
    last_seen_at: str
    last_fixed_on: Optional[str] = None
    status: Literal["open", "closed"]
    details: Optional[str] = None
    port: Optional[int] = None
    vuln_def_name: str


class Findings(BaseModel):
    """
    Model for findings of an asset
    """
    scanner_identifier: str = Field(..., description="Uniquely identifies data coming from a scanner.")
    scanner_type: str = Field(...,
                              description="Identifies the scanner the data came from. Paired with scanner_identifier (see above). ")
    created_at: Optional[str] = Field(None,
                                      description="ISO8601 timestamp indicating when the vulnerability was first found by the scanner. "
                                                  "Defaults to current date if not provided.")
    due_date: Optional[str] = None
    last_seen_at: str
    severity: Optional[int] = Field(None,
                                    description="Score given by the scanner. [0..10] Used for scoring. "
                                                "Normalized to a Cisco Vulnerability Management Risk Score by multiplying x 10. ")
    triage_state: Optional[str] = None
    additional_fields: Optional[Dict[str, Any]] = None
    vuln_def_name: str


class KennaAsset(BaseModel):
    """
    Model for Kenna assets
    """
    # locator fields
    file: Optional[str] = None
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    ec2: Optional[str] = None
    netbios: Optional[str] = None
    url: Optional[str] = None
    fqdn: Optional[str] = None
    image_id: Optional[str] = None
    container_id: Optional[str] = None
    external_id: Optional[str] = None
    database: Optional[str] = None

    # other asset fields
    application: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    owner: Optional[str] = None
    os: Optional[str] = None
    os_version: Optional[str] = None
    priority: Optional[int] = 10
    asset_type: Optional[Literal["container", "image"]] = None
    last_seen_at: Optional[str] = Field(None,
                                        description="ISO8601 timestamp indicating when the asset was last observed.")
    vulns: List[Vulnerability] = Field(default_factory=list)
    findings: List[Findings] = Field(default_factory=list)


class KennaDataImporter(BaseModel):
    """
    Root model for Kenna Data Importer.

    https://help.kennasecurity.com/hc/en-us/articles/360026413111-Data-Importer-JSON-Connector
    """
    skip_autoclose: bool = Field(False,
                                 description="If true, suppresses the closing of vulnerabilities missing from assets in this payload.")
    version: int = Field(2,
                         description="The version of the Data Importer format. The value should be '2'.")
    reset_tags: Optional[bool] = Field(False,
                                       description="Used to determine if ALL tags should be wiped from an asset before the tags defined in the Data Importer upload files are applied.")
    assets: List[KennaAsset] = Field(default_factory=list)
    vuln_defs: List[KennaVulnDef] = Field(default_factory=list)


class KennaDataExportAssets(BaseModel):
    meta: Dict[Literal["total_count"], int]
    assets: List[Dict[str, Any]]


class KennaDataExportVulns(BaseModel):
    meta: Dict[Literal["total_count"], int]
    vulnerabilities: List[Dict[str, Any]]


class KennaDataExportModel(RootModel):
    root: KennaDataExportAssets | KennaDataExportVulns
