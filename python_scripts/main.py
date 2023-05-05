from pyspark.sql import SparkSession
import vt
from df_parser import DFParser
from find_public_ca import FindPublicCa
from intercept_data_finder import InterceptDataFinder
import os
import sys
import nest_asyncio
from datetime import datetime


def process_parquet(SQLContext: SparkSession, file_path: str, result_dir: str, virus_total_key: str, data_date: datetime):
    
    whitelist_file_path = "/home/ubuntu/GitLab/ssl_interception/lists/whitelist.txt"
    blacklist_file_path = "/home/ubuntu/GitLab/ssl_interception/lists/blacklist.txt"
    scanned_domains = "/home/ubuntu/GitLab/ssl_interception/lists/scanned_domains.txt"

    #Parse the data to get issuer and domain
    parser = DFParser(SQLContext, file_path)
    df = parser.get_issuer_and_domain()

    #Get the public CAs, put into whitelist.txt
    ca_finder = FindPublicCa(SQLContext, df, whitelist_file_path)
    ca_finder.update_whitelist()

    # Create Virus Total Key
    client = vt.Client(virus_total_key)

    #Query Virus Total and Get Historical CAs, Save to Parquet
    intercept_data_finder = InterceptDataFinder(client, df, whitelist_file_path, blacklist_file_path, scanned_domains, data_date=data_date)
    intercept_data_finder.get_historical_df(file_path, result_dir)

def main():
    # Indicate where python3 is located
    nest_asyncio.apply()
    os.environ['PYSPARK_PYTHON'] = sys.executable
    os.environ['PYSPARK_DRIVER_PYTHON'] = sys.executable

    SQLContext = SparkSession.builder.master("local[1]") \
        .appName("session-0") \
        .getOrCreate()
    
    data_path = f"/mnt/chaseproject/uva/kd5eyn/ssl/{sys.argv[1]}/"
    result_path = f"/mnt/chaseproject/uva/kd5eyn/intercept_data/{sys.argv[1]}/"
    #parquets = os.listdir(data_path)
    parquets = os.listdir(data_path)
    data_date = datetime.strptime(sys.argv[1], "%Y-%m-%d")

    #Create client for Virus Total
    api_key_file = open("/home/ubuntu/GitLab/ssl_interception/virus_total_api_key", "r")
    api_key = api_key_file.readline()
    api_key_file.close()
    
    for parquet_name in parquets[(2*len(parquets)//3):]:
        try:
            process_parquet(SQLContext, data_path + parquet_name, result_path, data_date, api_key)
        except Exception as e:
            print(e)
    


if __name__ == "__main__":
    main()