from pycrtsh import Crtsh
from tldextract import extract
from datetime import datetime
from typing import Dict, List


def find_closest_certs(cert_dict: Dict, data_date: datetime) -> List:
    closest_certs = []
    for ca_name in cert_dict.keys():
        certs = cert_dict[ca_name]
        closest = certs[0]
        for cert in certs:
            #If overlap
            if cert["not_before"] < data_date and cert["not_after"] > data_date:
                closest = cert
                break
            if cert["not_before"] - data_date < closest["not_before"] - data_date:
                closest = cert
        closest_not_before = closest["not_before"].strftime("%Y-%m-%d")
        latest_not_after = closest["not_after"].strftime("%Y-%m-%d")
        closest_certs.append(f"{ca_name} ({closest_not_before} - {latest_not_after})")
    return closest_certs

def find_latest_all(cert_dict: Dict) -> List:
    latest_certs = []
    for ca_name in cert_dict.keys():
        certs = cert_dict[ca_name]
        latest = certs[0]
        for cert in certs:
            if cert["not_after"] > latest["not_after"]:
                latest = cert
        latest_not_before = latest["not_before"].strftime("%Y-%m-%d")
        latest_not_after = latest["not_after"].strftime("%Y-%m-%d")
        latest_certs.append(f"{ca_name} ({latest_not_before} - {latest_not_after})")
    return latest_certs

def parse_crt(crt_parser: Crtsh, domain: str):
    certificates = crt_parser.search(domain)
    if len(certificates) == 0:
        url_parts = extract(domain)
        certificates = crt_parser.search(f"*.{url_parts.domain}.{url_parts.suffix}")
    
    if len(certificates) == 0:
        return ""
    
    cert_dict = {}
    for certificate in certificates:
        ca_name = certificate['ca']['parsed_name']['O']
        ca_data = {"name": ca_name, "not_before": certificate["not_before"], "not_after":certificate["not_after"] }
        if ca_name not in cert_dict:
            cert_dict[ca_name] = [ca_data]
        else:
            cert_dict[ca_name].append(ca_data)
    data_date = datetime.strptime("2019-3-15", "%Y-%m-%d")
    closest_certs = find_closest_certs(cert_dict, data_date)
    print(cert_dict)
    print(closest_certs)

def main():
    crt_parser = Crtsh()
    parse_crt(crt_parser=crt_parser, domain="careeverywhere.gmh.edu")

if __name__ == "__main__":
    main()