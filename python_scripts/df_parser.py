from pyspark.sql import SparkSession
from tldextract import extract
from pyspark.sql.functions import udf
from pyspark.sql.functions import col
from pyspark.sql.functions import StringType
from pyspark.sql.dataframe import DataFrame

class DFParser:

    def __init__(self, session: SparkSession, data_path: str):
        self.SQLContext = session
        self.df = self.SQLContext.read.parquet(data_path)
        self.data_path = data_path
    
    @staticmethod
    def get_issuer_org(issuer_str: str):
        if type(issuer_str) == str:
            o_index = issuer_str.find("O=")
            comma_index = issuer_str.find(",", o_index)
            #Get characters starting from after O= and before ,
            org_str = issuer_str[o_index + 2 :comma_index]
            return org_str.replace("\\", "")

    @staticmethod
    def get_domain(server_name_str: str):
        if type(server_name_str) == str:
            url_parts = extract(server_name_str)
            subdomain = url_parts.subdomain
            domain = url_parts.domain
            #tld - top level domain
            tld = url_parts.suffix
            if len(subdomain) > 0:
                return f"{subdomain}.{domain}.{tld}"
            return f"{domain}.{tld}"
    
    def get_issuer_column(self):
        x509_df_path = self.data_path.replace("ssl", "x509")
        x509_df = self.SQLContext.read.parquet(x509_df_path)
        x509_df = x509_df.select(["fingerprint", "certificate_issuer"])
        ssl_df = self.df.withColumn("fingerprint", self.df.cert_chain_fps[0])
        ssl_df = ssl_df.join(x509_df, on="fingerprint", how="inner")
        ssl_df = ssl_df.withColumnRenamed("certificate_issuer", "issuer")
        return ssl_df
        
    
    def set_issuer_and_domain(self):
        issuer_org_udf = udf(lambda issuer_str: DFParser.get_issuer_org(issuer_str), StringType())
        domain_udf = udf(lambda server_name: DFParser.get_domain(server_name), StringType())
        if "issuer" not in self.df.columns:
            self.df = self.get_issuer_column()
        self.df = self.df.withColumn("issuer_O", issuer_org_udf(col("issuer")))
        self.df = self.df.withColumn("domain", domain_udf(col("server_name")))
    
    def get_x509_columns(self):
        x509_df_path = self.data_path.replace("ssl", "x509")
        x509_df = self.SQLContext.read.parquet(x509_df_path)
        x509_df = x509_df.drop("_lpp_ver", "ts")
        if "cert_chain_fuids" in self.df.columns:
            ssl_df = self.df.withColumn("cert_id", self.df.cert_chain_fuids[0])
            x509_df = x509_df.withColumnRenamed("id", "cert_id")
            ssl_df = ssl_df.join(x509_df, on="cert_id", how="inner")
        else:
            ssl_df = self.df.withColumn("fingerprint", self.df.cert_chain_fps[0])
            ssl_df = ssl_df.join(x509_df, on="fingerprint", how="inner")
            ssl_df = ssl_df.withColumnRenamed("certificate_issuer", "issuer")
        return ssl_df
    
    def join_x509_ssl(self) -> DataFrame:
        issuer_org_udf = udf(lambda issuer_str: DFParser.get_issuer_org(issuer_str), StringType())
        domain_udf = udf(lambda server_name: DFParser.get_domain(server_name), StringType())
        self.df = self.get_x509_columns()
        self.df = self.df.withColumn("issuer_O", issuer_org_udf(col("issuer")))
        self.df = self.df.withColumn("domain", domain_udf(col("server_name")))
        return self.df
    
    def save_parquet(self, parquet_path):
        self.df.write.parquet(parquet_path)
    
    def get_issuer_and_domain(self) -> DataFrame:
        self.set_issuer_and_domain()
        return self.df

