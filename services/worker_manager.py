import os
import time

def start_worker():
    worker_type = os.getenv("WORKER_TYPE", "preprocessor")
    
    print(f"Starting worker: {worker_type}")
    
    # Simple delay to allow RabbitMQ and DB to be fully ready
    time.sleep(10)
    
    if worker_type == "preprocessor":
        from services.preprocessor import run
        run()
    elif worker_type == "session_builder":
        from services.session_builder import run
        run()
    elif worker_type == "analyzer":
        from services.analyzer import run
        run()
    elif worker_type == "reporter":
        from services.reporter import run
        run()
    else:
        print(f"Unknown worker type: {worker_type}")

if __name__ == "__main__":
    start_worker()
