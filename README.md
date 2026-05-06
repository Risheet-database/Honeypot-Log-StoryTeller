# 🍯 Honeypot Log Storyteller

An end-to-end AI pipeline that converts raw honeypot logs (Cowrie/Dionaea) into structured threat intelligence reports with MITRE ATT&CK mapping, attacker profiling, and LLM-based narration (powered by LLaMA-3 via Groq API).

## Features
- **File Ingestion**: Upload log files via a Streamlit Dashboard.
- **Microservices Architecture**: Processes events through Preprocessor, Session Builder, Analyzer, and Reporter workers via RabbitMQ queues.
- **LLM Narration**: Automatically generate analyst narratives with Groq LLaMA-3.
- **STIX 2.1 & MITRE Mapping**: Exports threat behaviors mapped to MITRE ATT&CK locally into PDF, JSON, and STIX 2.1 bundles.

## Tech Stack
- Frontend: **Streamlit**
- API: **FastAPI**
- Broker: **RabbitMQ**
- DB/Storage: **PostgreSQL**, **MinIO**
- AI/Processing: **Groq API**, **NLTK**, **SpaCy**, **ReportLab**, **stix2**

## Local Setup

1. Copy `.env.example` to `.env` (or just set the `GROQ_API_KEY` variable in `docker-compose.yml`).
```env
GROQ_API_KEY=your_groq_api_key_here
```

2. Spin up the cluster:
```bash
docker compose up --build -d
```

3. Access the interfaces:
- **Frontend Dashboard**: http://localhost:8501
- **FastAPI Docs**: http://localhost:8000/docs
- **MinIO Console**: http://localhost:9001 (minioadmin:minioadmin)
- **RabbitMQ Dashboard**: http://localhost:15672 (guest:guest)

4. Run tests:
```bash
docker compose exec backend pytest tests/
```

## Usage
1. Open the Dashboard at **http://localhost:8501**.
2. Go to the sidebar and upload `tests/sample_cowrie.json`.
3. Wait a few seconds for processing to finish.
4. Click "Refresh Sessions" and select the generated session.
5. Review the Analyst Narrative, Attacker Profile, and MITRE Heatmap.
6. Download the PDF, JSON, or STIX bundle.

## Deployment to Hugging Face Spaces (Docker Space)
1. Create a new "Docker" Space on Hugging Face.
2. Ensure you have standard variables set in Space Secrets:
   - `GROQ_API_KEY`
3. Modify the `backend.Dockerfile` and `frontend.Dockerfile` to expose correct ports and use Docker Compose natively if your HF space supports multi-container setups. 
*Note: HF Spaces typically map to a single App port 7860. You may need to use a single monolithic Dockerfile for HF Spaces that runs `supervisord` to start postgres, minio, rabbitmq, fastapi, and streamlit all in one container, or deploy the auxiliary services to an external cloud (ElephantSQL, CloudAMQP) and just run the web pieces in the HF Space.* The provided configuration `docker-compose.yml` models a scalable production deployment.
