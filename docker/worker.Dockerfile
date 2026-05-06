FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# NLTK and comprehensive SpaCy model for robust NLP
RUN python -c "import nltk; nltk.download('punkt')"
RUN pip install https://github.com/explosion/spacy-models/releases/download/en_core_web_md-3.6.0/en_core_web_md-3.6.0.tar.gz

COPY ./services /app/services
COPY ./shared /app/shared
COPY ./configs /app/configs

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# The command is overridden by docker-compose, or we use a clever entrypoint
CMD ["python", "services/worker_manager.py"]
