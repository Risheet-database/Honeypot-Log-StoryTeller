FROM python:3.10-slim

WORKDIR /app

COPY frontend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ./frontend /app/frontend
COPY ./shared /app/shared

ENV PYTHONPATH=/app

CMD ["streamlit", "run", "frontend/app.py", "--server.port=8501", "--server.address=0.0.0.0"]
