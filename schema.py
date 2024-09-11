from pydantic import BaseModel
from typing import List, Dict

class DomainFrequency(BaseModel):
    domain: str = None 
    matchinig_artifcats_from : int = 0 
    matching_artifacts_upto : int = 100
    matching_artifacts_ful_len : bool = False


class DomainFrequencyResponse(BaseModel):
    domain: str = None 
    subdomains : str = None
    frequency : int = 0,
    benign_frequency : int = 0,
    url : List = []
    matching_artifacts : Dict = {}
    bulks : Dict = {}



class PcapPath(BaseModel):

    pcap_path : str = None


class DomainInfo(BaseModel):
    url: List[str] = []
    domain: str = None
    subdomains: str = None
    frequency: int = 0
    # benign_frequency : int = 0

class ProcessPcapResponse(BaseModel):
    urls: List[str] = []
    domain: Dict[str,DomainInfo]


class FixFPFNArtifacts(BaseModel):
    artifact_id : str = None 
    domain_name : str = "" 
    flag : str = ""


class MatchingArtifacts(BaseModel):
    frequency : int = 5000

class MatchingBulks(BaseModel):
    domain_name : str = ""

class Potential_FNs(BaseModel):
    domain_name : str = ""
    artifact_id : str = ""