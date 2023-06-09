
import re
from get_all_ca_data_v2 import split_files
from main import process_parquet
from typing import List
from datetime import datetime
import os
from pyspark.sql import SparkSession
import threading
import sys
import email_sender

def get_parquet_folders(ssl_path: str, x509_path: str, start: datetime, end: datetime) -> List[str]:
    ssl_parquet_folders = os.listdir(ssl_path)
    x509_parquets = set(os.listdir(x509_path))

    available_ssl_parquets = []

    # Check all folders in the ssl folder
    for ssl_parquet_folder in ssl_parquet_folders:
        if not re.match("\d{4}-\d{2}-\d{2}$", ssl_parquet_folder):
            continue
        log_date = datetime.strptime(ssl_parquet_folder, "%Y-%m-%d")
        # If the folder's date falls in between the start and end date and we have a corresponding x509 folder
        if log_date >= start and log_date <= end and ssl_parquet_folder in x509_parquets:
            available_ssl_parquets.append(ssl_parquet_folder)
    
    return available_ssl_parquets

def intercept_one_day(ssl_dir: str, result_dir: str, api_key: str):
    ssl_files = os.listdir(ssl_dir)
    SQLContext = SparkSession.builder.master("local[1]") \
        .appName("session-0") \
        .getOrCreate()
    data_date = datetime.strptime(re.search("\d{4}-\d{2}-\d{2}$", ssl_dir).group(0), "%Y-%m-%d")
    print(data_date)
    for ssl_file in ssl_files:
        try:
            process_parquet(SQLContext, os.path.join(ssl_dir, ssl_file), result_dir, api_key, data_date)
        except:
            continue

def get_api_keys(api_file_path: str) -> List[str]:
    with open(api_file_path, "r") as api_file:
        return api_file.read().splitlines()

def process_all_in_range(start_date_str: str, end_date_str: str, ssl_path: str, x509_path: str, result_dir: str):
    start_date = datetime.strptime(start_date_str, "%Y-%m-%d")
    end_date = datetime.strptime(end_date_str, "%Y-%m-%d")
    result_path = os.path.join(result_dir, f"{start_date_str}_{end_date_str}") + "/"

    # Get Virus Total API Keys
    API_FILE_PATH = "/home/ubuntu/GitLab/ssl_interception/virus_total_api_key"
    api_keys = get_api_keys(API_FILE_PATH)

    parquet_folders = get_parquet_folders(ssl_path, x509_path, start_date, end_date)
    threads = []

    for i, parquet_folder in enumerate(parquet_folders):
        thread = threading.Thread(target=intercept_one_day, args=(os.path.join(ssl_path, parquet_folder), result_path, api_keys[i//2]))
        thread.start()
        threads.append(thread)
    
    for thread in threads:
        thread.join()

def main():
    os.environ['PYSPARK_PYTHON'] = sys.executable
    os.environ['PYSPARK_DRIVER_PYTHON'] = sys.executable
    BASE_DIR = "/mnt/chaseproject/uva/kd5eyn/"
    SSL_PATH = os.path.join(BASE_DIR, "ssl")
    X509_PATH = os.path.join(BASE_DIR, "x509")
    RESULT_PATH = os.path.join(BASE_DIR, "intercept_data")
    process_all_in_range(sys.argv[1], sys.argv[2], SSL_PATH, X509_PATH, RESULT_PATH)
    #process_all_in_range("2022-11-01", "2022-11-30", SSL_PATH, X509_PATH, RESULT_PATH)

    EMAIL_KEY_FILE = "/home/ubuntu/GitLab/ssl_interception/keys/brevo_key.txt"
    sender = email_sender.EmailSender(EMAIL_KEY_FILE)
    subject = f"Finished Finding Interceptors for Logs Between {sys.argv[1]} and {sys.argv[2]}"
    sender.send_email_to_self(subject, subject)

if __name__ == "__main__":
    main()

