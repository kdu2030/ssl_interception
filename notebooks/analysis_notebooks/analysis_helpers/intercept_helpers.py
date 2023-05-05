import pandas as pd
import os
import numpy as np
from datetime import datetime
from typing import List, Dict
from json import loads
import requests
from tldextract import extract
from pycrtsh import Crtsh
from traceback import print_exc


def combine_dfs(data_path: str) -> pd.DataFrame:
    # Get the first parquet file in the directory
    base_df = pd.read_parquet(data_path + os.listdir(data_path)[0])

    files = os.listdir(data_path)
    for file in files[1:]:
        tmp_df = pd.read_parquet(data_path + file)

        # Combine both dfs and drop duplicate rows
        base_df = pd.concat([base_df, tmp_df]).drop_duplicates()
        # Reset index - don't create a new df, and don't add an index column
        base_df.reset_index(inplace=True, drop=True)
    return base_df


def does_ca_match(zeek_ca: str, historical_cas: str) -> bool:
    # Converts historical_cas string into a set
    if historical_cas.find("{") == -1:
        return zeek_ca == historical_cas
    hist_cas_set = eval(historical_cas)
    if zeek_ca in hist_cas_set:
        return True
    return False


def remove_rows(base_df: pd.DataFrame) -> pd.DataFrame:
    # Remove rows where historical_ca is None, Unable to find, or Some Organization
    df = base_df[(base_df["historical_ca"] != "None") & (base_df["historical_ca"]
                                                         != "Unable to find") & (base_df["issuer_O"] != "SomeOrganization")]
    # Create a new column to check if the issuer organization is in one of the historical cas found
    df["does_ca_match"] = df.apply(lambda row: does_ca_match(
        row["issuer_O"], row["historical_ca"]), axis=1)
    return df[df["does_ca_match"] == False].copy()


def process_parquet_dir(data_path: str) -> pd.DataFrame:
    combined_df = combine_dfs(data_path=data_path)
    df = remove_rows(combined_df)
    df.drop("does_ca_match", axis=1, inplace=True)
    return df


def convert_to_tuple(value):
    return str(value)


def convert_np_array(df: pd.DataFrame) -> pd.DataFrame:
    return df.apply(convert_to_tuple)


def get_cert_validity(timestamp_str: str, not_before_str: str, not_after_str: str):
    timestamp_string = timestamp_str[:-8]
    not_before_string = not_before_str[:-8]
    not_after_string = not_after_str[:-8]
    timestamp = datetime.strptime(timestamp_string, "%Y-%m-%dT%H:%M:%S")
    not_before = datetime.strptime(not_before_string, "%Y-%m-%dT%H:%M:%S")
    not_after = datetime.strptime(not_after_string, "%Y-%m-%dT%H:%M:%S")
    return timestamp > not_before and timestamp < not_after


def get_num_days(not_before_str: str, not_after_str: str) -> int:
    not_before_string = not_before_str[:-8]
    not_after_string = not_after_str[:-8]
    not_before = datetime.strptime(not_before_string, "%Y-%m-%dT%H:%M:%S")
    not_after = datetime.strptime(not_after_string, "%Y-%m-%dT%H:%M:%S")
    return int((not_after - not_before).days)


def get_cert_valid_columns(df: pd.DataFrame) -> pd.DataFrame:
    df_valid_data = df.copy(deep=True)
    if "certificate_not_valid_before" not in df.columns or "certificate_not_valid_after" not in df.columns:
        raise Exception(
            "Dataframe needs to have valid before and valid after data")
    df_valid_data["cert_validity"] = df_valid_data.apply(lambda x: get_cert_validity(
        x.ts, x.certificate_not_valid_before, x.certificate_not_valid_after), axis=1)
    df_valid_data["num_days_valid"] = df_valid_data.apply(lambda x: get_num_days(
        x.certificate_not_valid_before, x.certificate_not_valid_after), axis=1)
    return df_valid_data


def get_cipher_suite_info(cipher_suites: List[str]) -> Dict[str, Dict]:
    cipher_suite_info = {}
    for cipher_suite in cipher_suites:
        url = f"https://ciphersuite.info/api/cs/{cipher_suite}"
        cipher_suite_info[cipher_suite] = loads(
            requests.get(url).content)[cipher_suite]
    return cipher_suite_info


def find_closest_certs(cert_dict: Dict, data_date: datetime) -> List:
    closest_certs = []
    for ca_name in cert_dict.keys():
        certs = cert_dict[ca_name]
        closest = certs[0]
        for cert in certs:
            # If overlap
            if cert["not_before"] < data_date and cert["not_after"] > data_date:
                closest = cert
                break
            if cert["not_before"] - data_date < closest["not_before"] - data_date:
                closest = cert
        closest_not_before = closest["not_before"].strftime("%Y-%m-%d")
        latest_not_after = closest["not_after"].strftime("%Y-%m-%d")
        closest_certs.append(
            f"{ca_name} ({closest_not_before} - {latest_not_after})")
    return closest_certs


def parse_crt(domain: str, date_str: str):
    try:
        crt_parser = Crtsh()
        certificates = crt_parser.search(domain)
        if len(certificates) == 0:
            url_parts = extract(domain)
            certificates = crt_parser.search(
                f"*.{url_parts.domain}.{url_parts.suffix}")

        cert_dict = {}

        # We use a dictionary because crt.sh logs all certificates for a single domain, even expired ones.
        for certificate in certificates:
            ca_name = certificate['ca']['parsed_name']['O']
            ca_data = {
                "name": ca_name, "not_before": certificate["not_before"], "not_after": certificate["not_after"]}
            if ca_name not in cert_dict:
                cert_dict[ca_name] = [ca_data]
            else:
                cert_dict[ca_name].append(ca_data)

        period_index = date_str.find(".")
        if period_index != -1:
            date_str = date_str[:period_index]
        date_datetime = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S")
        closest_certs = find_closest_certs(cert_dict, date_datetime)

        if len(closest_certs) == 0:
            return None
        elif len(closest_certs) == 1:
            return closest_certs[0]
        return str(closest_certs)

    except:
        # print_exc()
        return None


def fill_in_table(df: pd.DataFrame, cipher_suite_info: Dict[str, Dict], issuer_description: str = "") -> pd.DataFrame:
    domain_df = df[df["domain"].notnull()].copy(deep=True)
    domain_df.drop_duplicates(subset=["domain"], inplace=True)
    domain_data = {"domain": [], "2nd-level domain": [], "On-file leaf issuer": [], "Observed leaf issuer": [],
                   "Observed leaf serial number": [], "Observed issuer information/reference": [], "Weakness/vulnerabilities of interception parameters": []}
    weakness_data_format = "Validity Period: {validity_period}  Cipher Suite: {cipher_suite}  Cipher Security: {cipher_security}  TLS Version: {version}"

    for index, row in domain_df.iterrows():
        domain: str = row["domain"]
        domain_parts = extract(domain)
        domain_data["domain"].append(domain)

        second_level_domain = domain.replace(
            domain_parts.subdomain, "").replace(domain_parts.suffix, "").replace(".", "")
        domain_data["2nd-level domain"].append(second_level_domain)

        domain_data["On-file leaf issuer"].append(parse_crt(domain, row["ts"]))
        domain_data["Observed leaf issuer"].append(row["issuer_O"])

        domain_data["Observed leaf serial number"].append(
            row["certificate_serial"])
        domain_data["Observed issuer information/reference"].append(issuer_description)

        validity_period = str(get_num_days(
            row["certificate_not_valid_before"], row["certificate_not_valid_after"])) + " days"
        cipher_suite = row["cipher"]
        cipher_security = cipher_suite_info[cipher_suite]["security"]
        version = row["version"]

        domain_data["Weakness/vulnerabilities of interception parameters"].append(weakness_data_format.format(
            validity_period=validity_period, cipher_suite=cipher_suite, cipher_security=cipher_security, version=version))

    return pd.DataFrame.from_dict(domain_data)
