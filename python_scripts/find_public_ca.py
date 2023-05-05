from pyspark.sql import SparkSession
import pandas as pd
from pandas.core.frame import DataFrame
import os
import sys
from df_parser import DFParser
from pyspark.sql.dataframe import DataFrame

class FindPublicCa:

    def __init__(self, session: SparkSession, df: DataFrame, whitelist_path: str):
        self.SQLContext = session
        self.df = df.filter(df["validation_status"] == "ok")
        self.whitelist_path = whitelist_path
    
    
    def get_cas_df(self) -> pd.DataFrame:
        df_cas = self.df.dropDuplicates(["issuer_O"])
        df_cas = df_cas.toPandas()
        df_cas = df_cas.groupby(["issuer_O"])["server_name"].agg("count").reset_index(name="count")
        return df_cas
    
    def get_whitelist_set(self) -> set:
        file = open(self.whitelist_path, "r")
        return set(file.read().splitlines())

    def gen_whitelist(self, df_orgs: pd.DataFrame, whitelist_orgs: set):
        whitelist_file = open(self.whitelist_path, "r+")
        for org in df_orgs["issuer_O"]:
            if org not in whitelist_orgs:
                whitelist_orgs.add(org)
                whitelist_file.write(org + "\n")
        whitelist_file.close()
        return whitelist_orgs
    
    def update_whitelist(self):
        df_cas = self.get_cas_df()
        whitelist_set = self.get_whitelist_set()
        return self.gen_whitelist(df_cas, whitelist_set)
    

def main():
    os.environ['PYSPARK_PYTHON'] = sys.executable
    os.environ['PYSPARK_DRIVER_PYTHON'] = sys.executable
    SQLContext = SparkSession.builder.master("local[1]") \
        .appName("session-0") \
        .getOrCreate()
    data_file_path = "/home/ubuntu/parquet_data/2021-12-28.parquet"
    whitelist_file_path = "/home/ubuntu/GitLab/ssl_interception/whitelist.txt"
    parser = DFParser(SQLContext, data_file_path)
    df = parser.get_issuer_and_domain()
    ca_finder = FindPublicCa(SQLContext, df, whitelist_file_path)
    ca_finder.update_whitelist()
    

if __name__ == "__main__":
    main()
        

        

    

