import json
from minio import Minio
from io import BytesIO
from configs.settings import settings

class MinioClient:
    def __init__(self):
        self.client = Minio(
            settings.MINIO_ENDPOINT,
            access_key=settings.MINIO_ACCESS_KEY,
            secret_key=settings.MINIO_SECRET_KEY,
            secure=settings.MINIO_SECURE
        )
        
    def init_buckets(self):
        buckets = ["d1-raw-logs", "d5-reports"]
        for b in buckets:
            if not self.client.bucket_exists(b):
                self.client.make_bucket(b)

    def put_json(self, bucket_name: str, object_name: str, data: dict):
        json_data = json.dumps(data).encode('utf-8')
        data_stream = BytesIO(json_data)
        self.client.put_object(
            bucket_name,
            object_name,
            data_stream,
            length=len(json_data),
            content_type="application/json"
        )
        
    def put_file(self, bucket_name: str, object_name: str, file_path: str):
        self.client.fput_object(bucket_name, object_name, file_path)

    def get_json(self, bucket_name: str, object_name: str) -> dict:
        response = None
        try:
            response = self.client.get_object(bucket_name, object_name)
            data = json.loads(response.read().decode('utf-8'))
            return data
        except Exception as e:
            print(f"MinIO get_json error for {object_name}: {e}")
            raise e
        finally:
            if response:
                response.close()
            
minio_client = MinioClient()
