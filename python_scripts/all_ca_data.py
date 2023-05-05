from datetime import datetime, timedelta
from typing import List, Union
from pyspark.sql import SparkSession
from pyspark.sql.utils import AnalysisException
from pyspark.sql.dataframe import DataFrame
import os
from df_parser import DFParser
from pyspark.sql.functions import udf
from pyspark.sql.functions import col
from pyspark.sql.functions import StringType
import sys
import re
import magic


class CaDataFinder:
    def __init__(self, SQLContext: SparkSession, blacklist_path: str, ssl_path: str, x509_path: str, result_path: str):
        self.SQLContext = SQLContext
        self.blacklist = self.get_blacklist(blacklist_path)
        self.ssl_path = ssl_path
        self.x509_path = x509_path
        self.result_path = result_path
        self.file_checker = magic.Magic(mime=True)

    def get_blacklist(self, blacklist_path: str) -> List[str]:
        file = open(blacklist_path, "r")
        lines = file.read().splitlines()
        file.close()
        return lines

    # Start and end strings must be in YYYY-MM-DD format
    def get_date_strs(self, start: str, end: str) -> List[str]:
        start_date = datetime.strptime(start, "%Y-%m-%d")
        end_date = datetime.strptime(end, "%Y-%m-%d")
        ssl_folders = os.listdir(self.ssl_path)
        x509_folders = os.listdir(self.x509_path)

        date_strs = []

        for ssl_folder_name in ssl_folders:
            if not re.match("\d{4}-\d{2}-\d{2}$", ssl_folder_name):
                continue
            ssl_date = datetime.strptime(ssl_folder_name, "%Y-%m-%d")
            if ssl_folder_name in x509_folders and ssl_date >= start_date and ssl_date <= end_date:
                date_strs.append(ssl_folder_name)

        return date_strs

    def get_x509_columns(self, ssl_df: DataFrame, x509_df: DataFrame) -> DataFrame:
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

    def join_x509_ssl(self, ssl_df: DataFrame, x509_df: DataFrame) -> DataFrame:
        issuer_org_udf = udf(
            lambda issuer_str: DFParser.get_issuer_org(issuer_str), StringType())
        domain_udf = udf(lambda server_name: DFParser.get_domain(
            server_name), StringType())
        combined_df = self.get_x509_columns(ssl_df, x509_df)
        combined_df = combined_df.withColumn(
            "issuer_O", issuer_org_udf(col("issuer")))
        combined_df = combined_df.withColumn(
            "domain", domain_udf(col("server_name")))
        return combined_df

    def contains_ca(self, combined_df: DataFrame) -> bool:
        for ca_name in self.blacklist:
            if combined_df.filter(combined_df.issuer_O == ca_name):
                return True
        return False

    def save_parquet(self, df: DataFrame, file_path: str, result_dir: str):
        file_ext_index = file_path.rfind(".")
        file_name = file_path[:file_ext_index]
        parquet_file_name = f"{result_dir}{os.path.basename(file_name)}_ca.parquet"
        df.write.parquet(parquet_file_name)
        print(f"Saved {parquet_file_name}")

    def process_parquet(self, ssl_path: str, x509_path: str):
        try:
            ssl_df = self.SQLContext.read.parquet(ssl_path)
            x509_df = self.SQLContext.read.parquet(x509_path)
            combined_df = self.join_x509_ssl(ssl_df, x509_df)
            if self.contains_ca(combined_df):
                self.save_parquet(combined_df, ssl_path, self.result_path)
        except FileNotFoundError:
            print("SSL File or X509 File does not exist")
        except AnalysisException:
            print(f"Unable to infer type SSL: {ssl_path} X509: {x509_path}")

    def process_date(self, date_str: str):
        ssl_folder_path = self.ssl_path + date_str + "/"
        all_files = os.listdir(ssl_folder_path)

        for file_name in all_files:
            ssl_path = ssl_folder_path + file_name
            x509_path = ssl_folder_path.replace("ssl", "x509") + file_name.replace("ssl", "x509")
            
            if not os.path.exists(x509_path):
                continue
            
            if os.path.isdir(ssl_path) and os.path.isdir(x509_path):
                self.process_parquet(ssl_path, x509_path)
            elif os.path.splitext(ssl_path)[1] == ".parquet" and os.path.splitext(x509_path)[1] == ".parquet":
                self.process_parquet(ssl_path, x509_path)

    def get_date_parquets(self, start_date: str, end_date: str):
        date_strs = self.get_date_strs(start_date, end_date)
        for date_str in date_strs:
            self.process_date(date_str)


def main():
    os.environ['PYSPARK_PYTHON'] = sys.executable
    os.environ['PYSPARK_DRIVER_PYTHON'] = sys.executable

    BASE_DIR = "/mnt/chaseproject/uva/kd5eyn/"
    blacklist_path = "/home/ubuntu/GitLab/ssl_interception/lists/blacklist.txt"
    ssl_path = BASE_DIR + "ssl/"
    x509_path = BASE_DIR + "x509/"
    result_path = BASE_DIR + "all_ca_data/"

    SQLContext = SparkSession.builder.master("local[1]") \
        .appName("session-0") \
        .getOrCreate()

    data_finder = CaDataFinder(SQLContext=SQLContext,
                               blacklist_path=blacklist_path, ssl_path=ssl_path, x509_path=x509_path, result_path=result_path)
    data_finder.get_date_parquets(sys.argv[1], sys.argv[2])


if __name__ == "__main__":
    main()
