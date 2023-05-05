from ast import Str
from typing import Dict, List
import pyspark
from pyspark.sql import SparkSession
import pandas as pd
import os
from tldextract import extract
from pandas.core.frame import DataFrame
from pyspark.sql.functions import udf
from pyspark.sql.functions import col
from pyspark.sql.functions import StringType
import time
import vt
from pycrtsh import Crtsh
from tldextract import extract
from datetime import datetime


class InterceptDataFinder:
    def __init__(self, client: vt.Client, df: DataFrame, whitelist_path: str, blacklist_path: str, scanned_path: str, data_date: datetime):
        self.client = client
        self.crt_parser = Crtsh()
        self.df = self.get_connection_count(df)
        self.df = self.df.toPandas()
        self.whitelist_path = whitelist_path
        self.blacklist_path = blacklist_path
        self.scanned = scanned_path
        self.data_date = data_date
    
    def get_connection_count(self, conn_df: DataFrame):
        unknown_df = conn_df.filter(conn_df["validation_status"] == "unable to get local issuer certificate")
        unknown_df = unknown_df.groupBy(["domain", "issuer_O"]).count()
        unknown_df = unknown_df.withColumnRenamed("count", "conn_count")
        return unknown_df

    def get_list_set(self, path: str):
        file = open(path, "r")
        list_set = set(file.read().splitlines())
        file.close()
        return list_set

    @staticmethod
    def is_selfsigned(domain: str, issuer_O: str) -> bool:
        domain_lower = extract(domain.lower()).domain
        issuer_lower = issuer_O.lower().replace(" ", "")
        return domain_lower in issuer_lower

    def filter_df(self, whitelist: set, blacklist: set, scanned: set):
        df_filtered = self.df[~(self.df["issuer_O"].isin(
            whitelist) | self.df["issuer_O"].isin(blacklist) | self.df["domain"].isin(scanned))]
        df_filtered = df_filtered[df_filtered["domain"].str.contains(
            "None") == False]
        df_filtered = df_filtered[df_filtered["issuer_O"].str.contains(
            "None") == False]
        df_filtered = df_filtered[~df_filtered.apply(
            lambda x: InterceptDataFinder.is_selfsigned(x["domain"], x["issuer_O"]), axis=1)]
        df_filtered.reset_index(inplace=True)
        df_filtered.drop("index", axis=1)
        return df_filtered
    
    @classmethod
    def get_date_str(cls, date_time_str: str) -> str:
        t_index = date_time_str.find("T")
        space_index = date_time_str.find(" ")
        if t_index == -1 and space_index == -1:
            return date_time_str
        if t_index == -1:
            return date_time_str[space_index+1:]
        return date_time_str[t_index+1:]
    
    def find_closest_certs(self, cert_dict: Dict) -> List[str]:
        closest_certs = []
        for ca_name in cert_dict.keys():
            certs = cert_dict[ca_name]
            closest = certs[0]
            for cert in certs:
                #If overlap
                if cert["not_before"] < self.data_date and cert["not_after"] > self.data_date:
                    closest = cert
                    break
                if cert["not_before"] - self.data_date < closest["not_before"] - self.data_date:
                    closest = cert
            closest_not_before = closest["not_before"].strftime("%Y-%m-%d")
            latest_not_after = closest["not_after"].strftime("%Y-%m-%d")
            closest_certs.append(f"{ca_name} ({closest_not_before} - {latest_not_after})")
        return closest_certs
    
    @classmethod
    def find_latest_certs(cls, cert_dict: Dict) -> List[str]:
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

    def parse_crt(self, domain: str):
        try:
            certificates = self.crt_parser.search(domain)
            if len(certificates) == 0:
                url_parts = extract(domain)
                certificates = self.crt_parser.search(
                    f"*.{url_parts.domain}.{url_parts.suffix}")

            cert_dict = {}

            #We use a dictionary because crt.sh logs all certificates for a single domain, even expired ones.
            for certificate in certificates:
                ca_name = certificate['ca']['parsed_name']['O']
                ca_data = {"name": ca_name, "not_before": certificate["not_before"], "not_after":certificate["not_after"] }
                if ca_name not in cert_dict:
                    cert_dict[ca_name] = [ca_data]
                else:
                    cert_dict[ca_name].append(ca_data)
            closest_certs = self.find_closest_certs(cert_dict)
            
            if len(closest_certs) == 0:
                return None
            elif len(closest_certs) == 1:
                return closest_certs[0]
            return str(closest_certs)
            
        except:
            return None

    def parse_vt(self, domain: str):
        certificates = self.client.get_data(
            f"/domains/{domain}/historical_ssl_certificates")
        
        cert_dict = {}
        if len(certificates) == 0:
            url_parts = extract(domain)
            certificates = self.crt_parser.search(
                f"{url_parts.domain}.{url_parts.suffix}")

        for certificate in certificates:
            ca_name = certificate["attributes"]["issuer"]["O"]
            ca_data = ca_data = {"name": ca_name, "not_before": certificate["attributes"]["validity"]["not_before"], "not_after": certificate["attributes"]["validity"]["not_after"]}
            if ca_name not in cert_dict:
                cert_dict[ca_name] = [ca_data]
            else:
                cert_dict[ca_name].append(ca_data)
        
        closest_certs = self.find_closest_certs(cert_dict)

        if len(closest_certs) == 0:
            return "None"
        elif len(closest_certs) == 1:
            return closest_certs[0]

        return str(closest_certs)

    def get_historical_ca(self, df: pd.DataFrame, scanned: set):
        historical_df = df.copy()
        historical_df.reset_index(drop=True, inplace=True)
        historical_cas = []
        for index, row in historical_df.iterrows():
            domain = row["domain"]
            try:
                crt_cas = self.parse_crt(domain)
                if crt_cas is None:
                    historical_cas.append(self.parse_vt(domain))
                else:
                    historical_cas.append(crt_cas)
            except Exception as e:
                print(e)
                historical_cas.append("Unable to find")

        historical_df["historical_ca"] = historical_cas
        return historical_df

    def save_scanned(self, scanned: set):
        file = open(self.scanned, "w")
        for scanned_domain in scanned:
            file.write(scanned_domain + "\n")
        file.close()

    def save_historical_df(self, df: pd.DataFrame, source_file: str, dest_dir: str = "."):
        file_ext_index = source_file.rfind(".")
        src_file_name = source_file[:file_ext_index]
        parquet_file_name = f"{dest_dir}{os.path.basename(src_file_name)}_pos_intercept.parquet"
        df.to_parquet(parquet_file_name)
        return parquet_file_name

    def get_historical_df(self, source_parquet_name: str, dest_dir: str = "."):
        whitelist = self.get_list_set(self.whitelist_path)
        blacklist = self.get_list_set(self.blacklist_path)
        scanned = self.get_list_set(self.scanned)

        filtered_df = self.filter_df(whitelist, blacklist, scanned)
        historical_df = self.get_historical_ca(filtered_df, scanned)
        self.save_scanned(scanned)
        self.save_historical_df(historical_df, source_parquet_name, dest_dir)
