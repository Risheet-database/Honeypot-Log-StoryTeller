import pika
import json
from configs.settings import settings

import time

def get_rabbitmq_connection():
    params = pika.URLParameters(settings.RABBITMQ_URL)
    params.socket_timeout = 10
    
    retries = 10
    while retries > 0:
        try:
            return pika.BlockingConnection(params)
        except Exception as e:
            print(f"[RabbitMQ] Connection failed, retrying in 5s... ({e})")
            time.sleep(5)
            retries -= 1
            
    raise Exception("[RabbitMQ] Critical: Failed to connect to RabbitMQ broker after multiple retries.")

def init_queues():
    conn = get_rabbitmq_connection()
    channel = conn.channel()
    queues = ["raw_events", "sessions_ready", "narration_jobs", "report_jobs"]
    for q in queues:
        channel.queue_declare(queue=q, durable=True)
    conn.close()

def publish_message(queue_name: str, message: dict):
    conn = get_rabbitmq_connection()
    channel = conn.channel()
    channel.basic_publish(
        exchange='',
        routing_key=queue_name,
        body=json.dumps(message),
        properties=pika.BasicProperties(
            delivery_mode=2,  # make message persistent
        ))
    conn.close()
