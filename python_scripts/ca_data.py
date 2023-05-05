from df_parser import DFParser
import os
import sys
import nest_asyncio
from pyspark.sql import SparkSession
from pyspark.sql.dataframe import DataFrame

def save_parquet(df: DataFrame, file_path: str, result_dir: str):
    file_ext_index = file_path.rfind(".")
    file_name = file_path[:file_ext_index]
    parquet_file_name = f"{result_dir}{os.path.basename(file_name)}_ca.parquet"
    df.write.parquet(parquet_file_name)


def process_parquet(SQLContext: SparkSession, ca: str, file_path: str, result_dir: str):
     #Parse the data to get issuer and domain
    parser = DFParser(SQLContext, file_path)
    df = parser.join_x509_ssl()
    issuer_df = df.filter(df.issuer_O == ca)
    if issuer_df.count() > 0:
        save_parquet(issuer_df, file_path, result_dir)

def main():
    # Indicate where python3 is located
    nest_asyncio.apply()
    os.environ['PYSPARK_PYTHON'] = sys.executable
    os.environ['PYSPARK_DRIVER_PYTHON'] = sys.executable

    SQLContext = SparkSession.builder.master("local[1]") \
        .appName("session-0") \
        .getOrCreate()
    
    data_path = f"/mnt/chaseproject/uva/kd5eyn/ssl/{sys.argv[1]}/"
    
    result_dir_name = sys.argv[2].lower().replace(" ", "_")
    
    result_path = f"/mnt/chaseproject/uva/kd5eyn/ca_data/{result_dir_name}/"
    parquets = os.listdir(data_path)
    
    for parquet_name in parquets[(2*len(parquets)//3):]:
        try:
            process_parquet(SQLContext, sys.argv[2], data_path + parquet_name, result_path)
        except Exception as e:
            print(e)

if __name__ == "__main__":
    main()