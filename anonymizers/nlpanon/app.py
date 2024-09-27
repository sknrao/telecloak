from testingFineTunedNER import anonymize_seq
from minio import Minio
import os
import glob
import requests

minio_client = None

def list_object():
    bucket='input'
    anom='nlp'
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
    log_files = glob.glob(os.path.join(folder_path, '*.log'))
    
    for log_file in log_files:
        with open(log_file, 'r') as file:
            lines = file.readlines()
        print(log_file)
        # Anonymize each line in the log file
        anonymized_lines = [anonymize_seq(line) for line in lines]

        # Save the anonymized file (you can overwrite or create a new file)
        with open(log_file, 'w') as file:
            file.writelines(anonymized_lines)
        
        put_object('output',log_file,'nlp')

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


    