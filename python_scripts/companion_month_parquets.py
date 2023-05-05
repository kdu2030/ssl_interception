import os
import re
import copy
from typing import List
from pyspark.sql import SparkSession
from convert_parquets import convert_parquets
import threading
import sys


class CompanionMonthParquetConverter:

    def __init__(self, result_dir: str, data_dir: str, month: int, year: int, log_type: str, complement_log_type: str, num_days: int = 10):
        self.result_dir = result_dir
        self.data_dir = data_dir
        self.month = month
        self.year = year
        self.log_type = log_type
        self.complement_log_type = complement_log_type
        self.num_days = num_days

    def get_days(self) -> List[str]:
        month_year_str = f"{self.year}-{str(self.month).zfill(2)}"
        all_complement_dirs = os.listdir(
            self.result_dir + self.complement_log_type + "/")
        precomputed_dirs = os.listdir(self.result_dir + self.log_type + "/")

        complement_dirs = []
        for folder_name in all_complement_dirs:
            if re.match("\d{4}-\d{2}-\d{2}$", folder_name) and folder_name.find(month_year_str) != -1:
                complement_dirs.append(folder_name)

        need_to_compute = copy.deepcopy(complement_dirs)
        for folder_name in precomputed_dirs:
            if folder_name.find(month_year_str) != -1 and folder_name in complement_dirs:
                need_to_compute.remove(folder_name)

        return need_to_compute[:self.num_days+1]

    def convert_day(self, date_str: str):
        SQLContext = SparkSession.builder.master("local[2]") \
            .appName("session-1") \
            .getOrCreate()
        data_dir = f"{self.data_dir}/{date_str}/"
        result_dir = f"{self.result_dir}{self.log_type}/{date_str}/"
        convert_parquets(SQLContext, data_dir, result_dir, self.log_type)

    def convert_all_days(self):
        days_list = self.get_days()
        threads: List[threading.Thread] = []
        for day_str in days_list:
            threads.append(threading.Thread(
                target=self.convert_day, args=(day_str,)))

        for i, thread in enumerate(threads):
            print(f"Starting threads {i}")
            thread.start()

        for thread in threads:
            thread.join()


def main():
    RESULT_DIR = "/mnt/chaseproject/uva/kd5eyn/"
    DATA_DIR = "/mnt/data/border/uva/zeek/"
    companion_month_parser = CompanionMonthParquetConverter(
        result_dir=RESULT_DIR, data_dir=DATA_DIR, month=sys.argv[1], year=sys.argv[2], log_type=sys.argv[3], complement_log_type=sys.argv[4])
    companion_month_parser.convert_all_days()


if __name__ == "__main__":
    main()
