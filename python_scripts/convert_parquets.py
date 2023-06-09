from typing import List
import pyspark
from pyspark.sql import SparkSession
import pandas as pd
import os
from tldextract import extract
from pandas.core.frame import DataFrame
import sys

def search_files(source_dir: str, search_term: str) -> List[str]:
    filepaths = []
    for filename in os.listdir(source_dir):
        if search_term in filename:
            filepaths.append(source_dir + filename)
    return filepaths
    
def convert_parquets(session: SparkSession, data_dir: str, save_dir: str, search_term: str = "ssl"):
    logs = search_files(data_dir, search_term)
    for log in logs:
        data_json = session.read.json(log)
        data_json.write.parquet(save_dir + os.path.basename(log))
        print(f"Finish converting {os.path.basename(log)}")

def main():
    SQLContext = SparkSession.builder.master("local[2]") \
                .appName("session-1") \
                .getOrCreate()
    #Call using python3 convert_parquets.py date_str search_term
    date_str = sys.argv[1]
    #/mnt/chaseproject/uva/kd5eyn/ssl/2022-04-15
    #/home/ubuntu/data/ssl/{date_str}/
    search_term = sys.argv[2]
    convert_parquets(SQLContext, f"/mnt/data/border/uva/zeek/{date_str}/", f"/mnt/chaseproject/uva/kd5eyn/{search_term}/{date_str}/", search_term=search_term)
if __name__ == "__main__":
    main()