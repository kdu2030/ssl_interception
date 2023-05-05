import os
from calendar import monthrange
import re
from random import randint
from convert_parquets import convert_parquets
from typing import List
from pyspark.sql import SparkSession
import threading
import sys

class MonthParquetConverter:

    def __init__(self, result_dir: str, data_dir:str, month: int, year: int, log_type: str, num_days: int = 10):
        # Result dir should contain ssl and x509 folders
        self.data_dir = data_dir
        self.result_dir = result_dir
        self.month = month
        self.year = year
        self.log_type = log_type
        self.num_days = num_days

    
    # Get a random list of days to convert to parquets
    def get_days(self) -> List[str]:
        month_year_str = f"{self.year}-{str(self.month).zfill(2)}"
        pre_computed_dirs = os.listdir(self.result_dir + self.log_type + "/")
        
        # Get number of days in month
        # The zeroth element in the return value is the weekday of the first day of the month
        num_days = monthrange(self.year, self.month)[1]
        days_list = list(range(1, num_days + 1))
        num_days_precomputed = 0
        
        for folder_name in pre_computed_dirs:
            if re.match("\d{4}-\d{2}-\d{2}$", folder_name) and folder_name.find(month_year_str) != -1:
                day_str = folder_name[8:]
                days_list.remove(int(day_str))
                num_days_precomputed += 1
        
        days_to_compute = []

        if num_days_precomputed < self.num_days:
            for i in range(self.num_days - num_days_precomputed):
                random_i = randint(0, len(days_list) - 1)
                random_day = days_list.pop(random_i)
                days_to_compute.append(str(random_day).zfill(2))
        
        return days_to_compute
    
    def convert_day(self, day_str: str):
        SQLContext = SparkSession.builder.master("local[2]") \
                .appName("session-1") \
                .getOrCreate()
        day_data_str = f"{self.year}-{str(self.month).zfill(2)}-{day_str}/"
        data_dir = f"{self.data_dir}{day_data_str}"
        result_dir = f"{self.result_dir}{self.log_type}/{day_data_str}"
        convert_parquets(SQLContext, data_dir, result_dir, self.log_type)
    
    def convert_all_days(self):
        days_list = self.get_days()
        threads: List[threading.Thread] = []
        for day_str in days_list:
            threads.append(threading.Thread(target=self.convert_day, args=(day_str,)))
        
        for i, thread in enumerate(threads):
            print(f"Starting threads {i}")
            thread.start()
        
        for thread in threads:
            thread.join()
        

    


def main():
    RESULT_DIR = "/mnt/chaseproject/uva/kd5eyn/"
    DATA_DIR = "/mnt/data/border/uva/zeek/"
    month_parser = MonthParquetConverter(result_dir=RESULT_DIR, data_dir=DATA_DIR, month=int(sys.argv[1]), year=int(sys.argv[2]), log_type=sys.argv[3])
    month_parser.convert_all_days()

if __name__ == "__main__":
    main()
        