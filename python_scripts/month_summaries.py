import os
from datetime import datetime
from typing import List, Dict
import re
from pyspark.sql import SparkSession, DataFrame
from df_parser import DFParser
from pyspark.sql.functions import udf
from pyspark.sql.functions import col
from pyspark.sql.functions import StringType
import sys
import requests
from json import loads
import threading

def get_directories_in_range(base_dir: str, start_date_str: str, end_date_str: str) -> Dict[str, List[str]]:
    folders = os.listdir(base_dir)
    start_date = datetime.strptime(start_date_str, "%Y-%m-%d")
    end_date = datetime.strptime(end_date_str, "%Y-%m-%d")
    directories_in_range = {}
    for folder in folders:
        if not re.match("\d{4}-\d{2}-\d{2}$", folder):
            continue

        folder_date = datetime.strptime(folder, "%Y-%m-%d")
        if folder_date >= start_date and folder_date <= end_date:
            if not folder_date.month in directories_in_range.keys():
                directories_in_range[folder_date.month] = [folder]
            else:
                directories_in_range[folder_date.month].append(folder)
    return directories_in_range

def get_x509_columns(ssl_df: DataFrame, x509_df: DataFrame) -> DataFrame:
        x509_df = x509_df.drop("_lpp_ver", "ts")
        if "cert_chain_fuids" in ssl_df.columns:
            ssl_df = ssl_df.withColumn("cert_id", ssl_df.cert_chain_fuids[0])
            x509_df = x509_df.withColumnRenamed("id", "cert_id")
            ssl_df = ssl_df.join(x509_df, on="cert_id", how="inner")
        else:
            ssl_df = ssl_df.withColumn("fingerprint", ssl_df.cert_chain_fps[0])
            ssl_df = ssl_df.join(x509_df, on="fingerprint", how="inner")
            ssl_df = ssl_df.withColumnRenamed("certificate_issuer", "issuer")
        return ssl_df

def get_blacklist(blacklist_path: str) -> List[str]:
    with open(blacklist_path, "r") as file:
        return file.read().splitlines()

def get_cipher_suite_info(cipher_suites: List[str]) -> Dict[str, Dict]:
    #print(cipher_suites)
    cipher_suite_info = {}
    for cipher_suite in cipher_suites:
        url = f"https://ciphersuite.info/api/cs/{cipher_suite}"
        try:
            cipher_suite_info[cipher_suite] = loads(requests.get(url).content)[cipher_suite]
        except:
            cipher_suite_info[cipher_suite] = "Data Not Found"
    return cipher_suite_info

def get_cipher_security(df: DataFrame) -> Dict[str, str]:
    cipher_suites = []
    cipher_suite_rows = df.select(col("cipher")).distinct().collect()
    for row in cipher_suite_rows:
        cipher_suites.append(row[0])
    cipher_suite_info = get_cipher_suite_info(cipher_suites)
    cipher_security = {"weak": [], "recommended": [], "secure": []}
    for cipher, cipher_description in cipher_suite_info.items():
        try:
            if cipher_description["security"] in cipher_security:
                cipher_security[cipher_description["security"]].append(cipher)
            else:
                cipher_security[cipher_description["security"]] = []
                cipher_security[cipher_description["security"]].append(cipher)
        except:
            continue
    return cipher_security


def join_x509_ssl(ssl_df: DataFrame, x509_df: DataFrame) -> DataFrame:
    issuer_org_udf = udf(
        lambda issuer_str: DFParser.get_issuer_org(issuer_str), StringType())
    domain_udf = udf(lambda server_name: DFParser.get_domain(
        server_name), StringType())
    combined_df = get_x509_columns(ssl_df, x509_df)
    combined_df = combined_df.withColumn(
        "issuer_O", issuer_org_udf(col("issuer")))
    combined_df = combined_df.withColumn(
        "domain", domain_udf(col("server_name")))
    return combined_df


def get_parquet_data(ssl_df: DataFrame, x509_df: DataFrame, blacklist: List[str]) -> Dict[str, int]:
    combined_df = join_x509_ssl(ssl_df, x509_df)
    data = {}
    data["num_conns"] = combined_df.count()
    cert_df = combined_df.dropDuplicates(["issuer_O", "certificate_serial"])
    data["num_certs"] = cert_df.count()
    intercept_df = combined_df.filter(col("issuer_O").isin(blacklist))
    data["intercept_conns"] = intercept_df.count()
    data["num_intercept_certs"] = intercept_df.dropDuplicates(["issuer_O", "certificate_serial"]).count()
    non_intercept_df = combined_df.filter(~col("issuer_O").isin(blacklist))
    data["non_intercept_conns"] = non_intercept_df.count()
    data["num_non_intercept_certs"] = non_intercept_df.dropDuplicates(["issuer_O", "certificate_serial"]).count()

    cipher_security = get_cipher_security(non_intercept_df)
    for cipher_classification, cipher_list in cipher_security.items():
        security_df = non_intercept_df.filter(col("cipher").isin(cipher_list))
        security_df = security_df.dropDuplicates(["issuer_O", "certificate_serial"])
        data[f"non_intercept_{cipher_classification}"] = security_df.count()
    return data
    

def process_one_day(SQLContext: SparkSession, base_dir: str, dir_name: str, blacklist_path: str) -> Dict[str, int]:
    day_dir_path = os.path.join(base_dir, dir_name)
    parquet_files = os.listdir(day_dir_path)
    data = {}
    blacklist = get_blacklist(blacklist_path=blacklist_path)
    for parquet_path in parquet_files:
        try:
            ssl_df = SQLContext.read.parquet(os.path.join(day_dir_path, parquet_path))
            x509_df = SQLContext.read.parquet(os.path.join(day_dir_path, parquet_path).replace("ssl", "x509"))
        except:
            continue
        parquet_data = get_parquet_data(ssl_df, x509_df, blacklist)
        for key, value in parquet_data.items():
            if key not in data:
                data[key] = value
            else:
                data[key] += value
    return data

def write_output(result_file: str, month: str, month_data: Dict):
    with open(result_file, "a+") as file:
        file.write(f"{month}: \n")
        for data_item, data in month_data.items():
            file.write(f"{data_item}: {data} \n")

def process_all(SQLContext: SparkSession, base_dir: str, blacklist_path: str, month_days: Dict[str, List[str]], result_file: str):
    for month, days in month_days.items():
        month_data = {}
        for day in days:
            day_data = process_one_day(SQLContext, base_dir, day, blacklist_path)
            
            for key, value in day_data.items():
                if key not in month_data:
                    month_data[key] = value
                else:
                    month_data[key] += value
        
        write_output(result_file, month, month_data)
    
        

    
    

def main():
    BASE_DIR = "/mnt/chaseproject/uva/kd5eyn/ssl/"
    BLACKLIST_PATH = "/home/ubuntu/GitLab/ssl_interception/lists/blacklist.txt"
    test_ssl_path = "/mnt/chaseproject/uva/kd5eyn/ssl/2022-01-01/anon.ssl_20220101_0000-0030-0500.log.gz/"
    test_x509_path = test_ssl_path.replace("ssl", "x509")
    
    os.environ['PYSPARK_PYTHON'] = sys.executable
    os.environ['PYSPARK_DRIVER_PYTHON'] = sys.executable
    
    SQLContext = SparkSession.builder.master("local[1]") \
        .appName("session-0") \
        .getOrCreate()
    
    # print(process_one_day(SQLContext, BASE_DIR, "2022-01-01", BLACKLIST_PATH))

    directories = get_directories_in_range(BASE_DIR, "2022-02-01", "2022-04-30")
    process_all(SQLContext, BASE_DIR, BLACKLIST_PATH, directories, "month_data.txt")


if __name__ == "__main__":
    main()