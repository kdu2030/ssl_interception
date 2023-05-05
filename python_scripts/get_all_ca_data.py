from pyspark.sql import SparkSession, DataFrame
from pyspark.sql.functions import lit
import os
import sys
import pandas as pd

def union_dfs(base_df: DataFrame, target_df: DataFrame) -> DataFrame:
    base_columns = set(base_df.columns)
    target_columns = set(target_df.columns)
    base_missing = target_columns.difference(base_columns)
    target_missing = base_columns.difference(target_columns)

    if "issuer" in target_missing:
        target_df = target_df.withColumnRenamed("certificate_issuer", "issuer")
        target_missing.remove("issuer")

    for column in base_missing:
        base_df = base_df.withColumn(column, lit(None))
    for column in target_missing:
        target_df = target_df.withColumn(column, lit(None))
    
    return base_df.unionByName(target_df)

def get_dfs(SQLContext: SparkSession, data_path: str) -> DataFrame:
    parquet_files = os.listdir(data_path)
    base_df = SQLContext.read.parquet(data_path + parquet_files[0])
    for parquet_file in parquet_files[1:]:
        try:
            df = SQLContext.read.parquet(data_path + parquet_file)
            base_df = union_dfs(base_df, df)
        except Exception as e:
            print(e)
            print(f"{parquet_file} unable to be read")
    return base_df

def main():
    os.environ['PYSPARK_PYTHON'] = sys.executable
    os.environ['PYSPARK_DRIVER_PYTHON'] = sys.executable
    DATA_PATH = "/mnt/chaseproject/uva/kd5eyn/all_ca_data/"
    SQLContext = SparkSession.builder.master("local[1]") \
            .appName("session-0") \
            .getOrCreate()
    df = get_dfs(SQLContext, DATA_PATH)
    df.write.parquet("/mnt/chaseproject/uva/kd5eyn/all_ca_data/all_interceptor_data.parquet")

if __name__ == "__main__":
    main()