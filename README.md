# Directories
* `keys` - This contains the API Key for Brevo, which is the email sending service that is used to notify when SSL Logs or X509 Logs have finished being converted into Parquet files. 
* `lists` - This contains the whitelist of non-SSL Interception issuers and the blacklist of SSL Interception issuers.
* `notebooks` - This contains Jupyter Notebooks. `notebooks > analysis_notebooks` are notebooks that can access the `analysis_helpers` package, which I wrote to simplify analyzing the results of parsing SSL and X509 Logs for potential SSL Interceptors
* `python_scripts` - This contains the Python files that convert SSL Logs and X509 Logs into Parquet files and parse those logs to find SSL Interception candidates
* `scripts` - This contains a bash script to access my data folder on my Sentinel VM.

# Data Prerequisites
* SSL and X509 Logs need be collected by Zeek
* The logs for each directory need to be stored in directories based on the date that they were collected. The directory name needs to be the date in the form of YYYY-MM-DD
* The file names need to correspond with the type of log that was collected.
  * e.g. an SSL log should have ssl in the filename.

# Python Scripts
* `ca_data.py` - For a single day's SSL and X509 Parquet Files, this parses through the parquet files, finds rows where the field issuer_O is equivalent to the user supplied issuer organization, and only copies the parquet files that have at least one row containing the issuer organization. Useful if you want to analyze traffic for a specific issuer organization.
  * Use: `python3 ca_data.py [date] [issuer organization]`
  * e.g. `python3 ca_data.py 2022-12-31 Intuitive`
  * Before use, change the `data_path` variable in the `main()` function to point to the folder that contains all the converted SSL parquet files. Additionally, change `result_path` to point to the folder where you want the resulting data 
* `convert_parquets.py` - This converts Zeek Logs to Parquet Files for a single day.
  * Use: `python3 convert_parquets.py [date] [type of log]`
  * e.g. `python3 convert_parquets.py 2022-04-15 ssl`
  * In `main()`, change the second argument of the `process_parquet()` call to point to the raw logs that Zeek recorded. Chagne the third argument of the `process_parquet()` call to where you want the parquet files to be saved.
* `crt_parser.py` - This is just used as an experiement Python program for using the pycrtsh library
* `df_parser.py` - This loads SSL logs and X509 logs from parquet files and converts them to PySpark dataframes. It also parses out the `issuer_O` field either using the `issuer` from the SSL logs or the `certificate_issuer` field from the X509 Logs.
* `email_sender.py` - This is a utility class that sends an email using the Brevo API. This class is used to notify users when logs have finished converting or when the SSL Interception data is found.
* `find_public_ca.py` - This is a class that parses the dataframe from `DFParser` for rows where Zeek has successfully validated the issuer (`validation_status == ok`). It will update the whitelist of certificate issuers.
* `get_all_ca_data.py` - This will find summary statistics for the dataset of SSL and X509 Logs. Additionally, among the rows where the issuer organization is on the blacklist of SSL interceptors, this will find the certificate validity period and the cipher suites that are used.
* `intercept_data_finder.py` - After the parquets are loaded by `DFParser` and the whitelist is updated by `FindPublicCa`, this class is meant to filter out any rows where the issuer organization is on the whitelist or already on the blacklist. This also queries crt.sh and Virus Total to find historical certificate issuers.
* `main.py` - This calles `DFParser`, `FindPublicCa`, and `InterceptDataFinder` to load parquet files into dataframes, update the whitelist, filter out rows, and find the historical issuers. This will only process a single day's SSL and X509 Logs.
  * Before use, edit `data_path` in the `main()` function to point to where the SSL parquets are located. Edit `result_path` in the `main()` function to point to where you want the results to be saved. Edit `api_key_file` to point to the file where the Virus Total API Key is saved.
  * Use: `python3 main.py [date]`
  * e.g. `python3 main.py 2022-04-15`
* `month_intercept_parser.py` - This is like `main.py` but will find interception data for all days within a range of days within a month.
  * Before use, edit `BASE_PATH` in `main()` to point to your project folder. This should be the place that contains the SSL Log and X509 Log parquets.
  * Use: `python3 month_intercept_parser.py [start date] [end date]`
  * e.g. `python3 month_intercept_parser.py 2023-01-01 2023-01-31`
* `month_parquets.py` - This is like `convert_parquets.py` except it chooses 10 random days within a range of days within a month, and converts Zeek logs for those days to parquet files.
  * Before use, change `DATA_DIR` to oint to the location of the Zeek logs and `RESULTS_DIR` to where the converted logs in parquet files should be saved.
  * Use: `python3 month_parquets.py [month] [year] [log type]`
  * e.g. `python3 month_parquets.py 2 2022 ssl`
* `companion_month_parquets.py` This converts the X509 logs that correspond to the logs that were converted with month_parquets.py.
  * Before use, change `DATA_DIR` to oint to the location of the Zeek logs and `RESULTS_DIR` to where the converted logs in parquet files should be saved.
  * Use: `python3 companion_month_parquets.py [month] [year] [log type] [companion log type]`
  * e.g. If we used `month_parquets.py` to convert SSL logs, we would do the following: `python3 companion_month_parquets.py 2 2022 x509 ssl`
* `month_summaries.py` - This is used to find summary statistics for a range of months.
* `save_ca_data.py` - This is like `ca_data.py` except it saves `ca data` for a range of days.
* To use: `python3 save_ca_data.py [start date] [end date]`
* e.g. `python3 save_ca_data.py 2022-10-01 2022-10-31`
  
# Finding Interception Data Example
1. Convert SSL Logs using `month_parquets.py` - `python3 month_parquets.py 12 2022 ssl`
2. Convert corresponding X509 Logs using `companion_month_parquets.py` - `python3 companion_month_parquets.py 12 2022 x509 ssl`
3. Parse the SSL logs and X509 logs in parquet files using `python3 month_intercept_parser 2022-12-01 2022-12-31`
4. Create a new notebook in `notebooks > analysis_notebooks`. Import `process_parquet_dir` from `analysis_helpers.intercept_helpers`. Set a new dataframe variable to `df = process_parquet_dir(<data path>)`



