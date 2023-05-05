import os
from datetime import datetime
from typing import List, Dict
import re
from pyspark.sql import SparkSession, DataFrame
from df_parser import DFParser
from pyspark.sql.functions import udf, col, StringType, array
import sys
import requests
from json import loads
from pyspark.sql.types import IntegerType
import threading
import numpy as np

file_lock = threading.Lock()

def get_num_days(not_before_str: str, not_after_str: str) -> int:
    not_before_string = not_before_str[:-8]
    not_after_string = not_after_str[:-8]
    not_before = datetime.strptime(not_before_string, "%Y-%m-%dT%H:%M:%S")
    not_after = datetime.strptime(not_after_string, "%Y-%m-%dT%H:%M:%S")
    return int((not_after - not_before).days)

def get_blacklist(blacklist_path: str) -> List[str]:
    with open(blacklist_path, "r") as file:
        return file.read().splitlines()

def split_files(data_path: str, num_threads: int = 8):
    all_files = os.listdir(data_path)
    thread_files = []
    for i in range(0, len(all_files), len(all_files)//num_threads):
        thread_files.append(all_files[i:i+(len(all_files)//num_threads)])
    return thread_files

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

def get_df_ciphers(df: DataFrame) -> List[str]:
    cipher_suites = []
    cipher_suite_rows = df.select(col("cipher")).distinct().collect()
    for row in cipher_suite_rows:
        cipher_suites.append(row[0])
    return cipher_suites

def get_cipher_security(df: DataFrame) -> Dict[str, str]:
    cipher_suites = get_df_ciphers(df)
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

def get_parquet_data(combined_df: DataFrame, blacklist: List[str]) -> Dict[str, int]:
    data = {}
    # data["num_conns"] = combined_df.count()
    # cert_df = combined_df.dropDuplicates(["issuer_O", "certificate_serial"])
    # data["num_certs"] = cert_df.count()
    intercept_df = combined_df.filter(col("issuer_O").isin(blacklist))
    data["intercept_conns"] = intercept_df.count()
    data["num_intercept_certs"] = intercept_df.dropDuplicates(["issuer_O", "certificate_serial"]).count()
    non_intercept_df = combined_df.filter(~col("issuer_O").isin(blacklist))
    data["non_intercept_conns"] = non_intercept_df.count()
    data["num_non_intercept_certs"] = non_intercept_df.dropDuplicates(["issuer_O", "certificate_serial"]).count()

    cipher_security = get_cipher_security(non_intercept_df)
    for cipher_classification, cipher_list in cipher_security.items():
        security_df = intercept_df.filter(col("cipher").isin(cipher_list))
        security_df = security_df.dropDuplicates(["issuer_O", "certificate_serial"])
        data[f"non_intercept_{cipher_classification}"] = security_df.count()
    
    ciphers = get_df_ciphers(intercept_df)
    for cipher in ciphers:
        cipher_df = intercept_df.dropDuplicates(["issuer_O", "cipher"])
        data[cipher] = intercept_df.filter(cipher_df.cipher == cipher).count()
    
    get_num_days_udf = udf(lambda not_before_str, not_after_str: get_num_days(not_before_str, not_after_str), IntegerType())
    intercept_df = intercept_df.withColumn("num_days_valid", get_num_days_udf(col("certificate_not_valid_before"), col("certificate_not_valid_after")))
    validity_df = intercept_df.groupBy(["issuer_O", "certificate_serial"]).agg({"num_days_valid": "avg"})
    validity_df = validity_df.withColumnRenamed("avg(num_days_valid)", "num_days_valid")
    
    bins, counts = validity_df.where(validity_df.num_days_valid > 800).select("num_days_valid").rdd.map(lambda x: x[0]).histogram(30)

    if len(bins) < 31:
        nums = list(range(31 - len(bins)))
        nums.extend(bins)
        bins = nums
    
    if len(counts) < 30:
        zeroes = [0] * (30 - len(counts))
        zeroes.extend(counts)
        counts = zeroes

    data["validity_period_counts_long"] = counts
    data["validity_period_bins_long"] = bins


    bins_no_outliers, counts_no_outliers = validity_df.where(validity_df.num_days_valid <= 800).select("num_days_valid").rdd.map(lambda x: x[0]).histogram(30)
    
    if len(bins_no_outliers) < 31:
        nums = list(range(31 - len(bins_no_outliers)))
        nums.extend(bins_no_outliers)
        bins_no_outliers = nums
    
    if len(counts_no_outliers) < 30:
        zeroes = [0] * (30 - len(counts_no_outliers))
        zeroes.extend(counts_no_outliers)
        counts_no_outliers = zeroes
    
    data["validity_period_counts_short"] = counts_no_outliers
    data["validity_period_bins_short"] = bins_no_outliers

    return data


def write_output(result_file: str, parquet_data: Dict):
    file_lock.acquire()
    with open(result_file, "a+") as file:
        file.write("\n")
        for data_item, data in parquet_data.items():
            file.write(f"{data_item}: {data} \n")
    file_lock.release()

def merge_histogram(bins1: List[float], counts1: List[int], bins2: List[float], counts2: List[int]):
    smallest_min = min(bins1[0], bins2[0])
    largest_max = max(bins1[-1], bins2[-1])
    
    # We need to rebin each of the histograms because they could have diffent ranges
    bins = np.linspace(smallest_min, largest_max, len(bins1))
    new_data1 = []
    new_data2 = []

    # for i, bin in enumerate(bins1):
    #     new_data1.extend([bin] * counts1[i])
    
    # for i, bin in enumerate(bins2):
    #     new_data2.extend([bin] * counts2[i])

    for i in range(len(bins1) - 1):
        new_data1.extend([(bins1[i] + bins1[i+1] / 2)] * counts1[i])
    
    for i in range(len(bins2) - 1):
        new_data2.extend([(bins2[i] + bins2[i+1] / 2)] * counts2[i])
    
    new_counts1, new_bins1 = np.histogram(np.array(new_data1), bins=bins)
    new_counts2, new_bins2 = np.histogram(np.array(new_data2), bins=bins)

    if len(new_counts1) < len(counts1):
        zeroes = [0] * (len(counts1) - len(new_counts1))
        zeroes.extend(new_counts1)
        new_counts1 = np.array(zeroes)
    
    if len(new_counts2) < len(counts2):
        zeroes = [0] * (len(counts2) - len(new_counts2))
        zeroes.extend(new_counts2)
        new_counts2 = np.array(zeroes)
    
    if len(new_bins1) < len(bins1):
        nums = list(range(len(bins1) - len(new_bins1)))
        nums.extend(new_bins1)
        new_bins1 = nums

    combined_counts = new_counts1 + new_counts2
    return list(new_bins1), list(combined_counts)


def process_subset(base_dir: str, parquet_files: List[str], blacklist: List[str], output_file) -> Dict[str, int]:
    SQLContext = SparkSession.builder.master("local[1]") \
        .appName("session-0") \
        .getOrCreate()
    subset_data = {}

    for parquet_file in parquet_files:
        path = os.path.join(base_dir, parquet_file)
        try:
            df = SQLContext.read.parquet(path)
            parquet_data = get_parquet_data(combined_df=df, blacklist=blacklist)
        except:
            continue
        
        
        for key, value in parquet_data.items():
            if key not in subset_data:
                subset_data[key] = value
            elif key == "validity_period_bins_long":
                subset_data["validity_period_bins_long"], subset_data["validity_period_counts_long"] = merge_histogram(subset_data["validity_period_bins_long"], subset_data["validity_period_counts_long"], parquet_data["validity_period_bins_long"], parquet_data["validity_period_counts_long"])
            elif key == "validity_period_bins_short":
                subset_data["validity_period_bins_short"], subset_data["validity_period_counts_short"] = merge_histogram(subset_data["validity_period_bins_short"], subset_data["validity_period_counts_short"], parquet_data["validity_period_bins_short"], parquet_data["validity_period_counts_short"])
            elif key == "validity_period_counts_long" or key == "validity_period_counts_short":
                continue
            else:
                subset_data[key] += value
    write_output(output_file, subset_data)
    return subset_data

def process_subset_modify(base_dir: str, parquet_files: List[str], blacklist: List[str], output_file: str, result: Dict):
    print("Thread start")
    subset_result = process_subset(base_dir, parquet_files, blacklist, output_file)
    for key, value in subset_result.items():
        result[key] = value

def process_all(base_dir: str, partitioned_files: List[List[str]], blacklist: List[str], output_file: str) -> Dict:
    
    threads = []
    results = []
    final_output = {}
    for i, partition in enumerate(partitioned_files):
        results.append({})
        thread = threading.Thread(target=process_subset_modify, args=(base_dir, partition, blacklist, output_file, results[i]))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    for result in results:
        for key, value in result.items():
            if key not in final_output:
                final_output[key] = value
            elif key == "validity_period_bins_long":
                final_output["validity_period_bins_long"], final_output["validity_period_counts_long"] = merge_histogram(final_output["validity_period_bins_long"], final_output["validity_period_counts_long"], result["validity_period_bins_long"], result["validity_period_counts_long"])
            elif key == "validity_period_bins_short":
                final_output["validity_period_bins_short"], final_output["validity_period_counts_short"] = merge_histogram(final_output["validity_period_bins_short"], final_output["validity_period_counts_short"], result["validity_period_bins_short"], result["validity_period_counts_short"])
            elif key == "validity_period_counts_long" or key == "validity_period_counts_short":
                continue
            else:
                final_output[key] += value
    
    with open(output_file, "a+") as file:
        file.write("Final output: \n")
    
    write_output(output_file, final_output)

    


def main():
    DATA_PATH = "/mnt/chaseproject/uva/kd5eyn/all_ca_data/"
    BLACKLIST_PATH = "/home/ubuntu/GitLab/ssl_interception/lists/blacklist.txt"
    os.environ['PYSPARK_PYTHON'] = sys.executable
    os.environ['PYSPARK_DRIVER_PYTHON'] = sys.executable
    
    # SQLContext = SparkSession.builder.master("local[1]") \
    #     .appName("session-0") \
    #     .getOrCreate()
    
    files = split_files(DATA_PATH)
    # print(process_subset(DATA_PATH, files[-1], get_blacklist(BLACKLIST_PATH), "test.txt"))
    process_all(DATA_PATH, files, get_blacklist(BLACKLIST_PATH), "all_ca_data_v3.txt")

if __name__ == "__main__":
    main()