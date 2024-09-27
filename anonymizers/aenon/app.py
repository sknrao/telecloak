from AE import anonymize_ae
from minio import Minio
import os
import glob
import requests
import pandas as pd

minio_client = None
 
def download_file(file_path):
    global logger
    url = f"{root_url}{file_path}"
    try:
        response = requests.get(url)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error downloading {file_path}: {e}")
        return None
    if response.status_code == 200:
        file_name = file_path.split("=")[-1]
        try:
            with open(file_name, 'wb') as file:
                # Write the content of the response to the file
                file.write(response.content)
            return file_path
        except IOError:
            return None
    else:
        return None
 
def list_object():
    bucket='input'
    anom='ae'
    global minio_client
    objects = minio_client.list_objects(bucket, prefix=anom, recursive=True)
    for obj in objects:
        print(obj.object_name)
        file_name = obj.object_name.split('/')[-1]
        file_path = os.path.join('data',file_name)
        minio_client.fget_object(bucket, obj.object_name, file_path)
 
def put_object(bucket, filepath, anon):
    global minio_client
 
    filename = os.path.basename(filepath)
    print(filename)
    result = minio_client.fput_object(bucket, 
                                      anon + "/" +filename, 
                                      filepath, 
                                      content_type="application/octet-stream")
 
def anonymize_logs_in_folder(folder_path):
    csv_files = glob.glob(os.path.join(folder_path, '*.csv'))
 
    for csv_file in csv_files:
        with open(csv_file, 'r') as file:
            lines = file.readlines()
        print(csv_file)
        # Anonymize each line in the log file
        output_df = anonymize_ae(csv_file)
 
        # Save the anonymized file (you can overwrite or create a new file)
        output_df.to_csv(csv_file, index=False)
 
        put_object('output',csv_file,'ae')
 
def main():
    global minio_client
    minio_client = Minio("minio-server:9000", 
                            access_key = "admin",
                            secret_key = "adminadmin",
                            secure=False)
    list_object()
    anonymize_logs_in_folder('data')
 
 
if __name__ == "__main__":
 
    main()
    # minio_client = None