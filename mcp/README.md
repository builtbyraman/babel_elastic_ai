MCP (Managed Conversion Platform) minimal scaffold

This folder contains a small scaffold for the Phase 3 MCP using FastAPI + Celery + Redis.

Services
- api: FastAPI application exposing /health, /v1/conversions, /v1/test-runs, /v1/jobs/{job_id}, and connector CRUD.
- worker: Celery worker that executes conversion and test-run tasks by proxying to the Phase 1 API (configured by MCP_API_BACKEND).
- redis: Redis broker for Celery (provided by docker-compose)
- postgres: PostgreSQL metadata store for jobs and connectors

Quick start (dev)

```bash
cd mcp
cp .env.example .env
# Start Redis, API and worker
docker-compose up --build

# Submit a conversion job
curl -X POST http://localhost:8000/v1/conversions -H "Content-Type: application/json" -d '{"rule_yaml":"title: Test\ndetection:\n  selection:\n    Image: test.exe\n  condition: selection","format":"eql","pipeline":"ecs_windows"}'

# Submit an Elasticsearch test-run job
curl -X POST http://localhost:8000/v1/test-runs -H "Content-Type: application/json" -d '{"rule_yaml":"title: Test\ndetection:\n  selection:\n    Image: test.exe\n  condition: selection","index_pattern":"*","timeframe_hours":24}'

# Query job status
curl http://localhost:8000/v1/jobs/<job_id>

# Create a secret for connector auth
curl -X POST http://localhost:8000/v1/secrets -H "Content-Type: application/json" -d '{"name":"elastic_api_key","type":"api_key","value":{"key":"<API_KEY>"}}'

# Create a connector
curl -X POST http://localhost:8000/v1/connectors -H "Content-Type: application/json" -d '{"name":"ES Cluster","type":"elasticsearch","endpoint":"http://elasticsearch:9200","auth_type":"api_key","credentials_ref":"elastic_api_key","metadata":{"region":"us-east-1"}}'

# List connectors
curl http://localhost:8000/v1/connectors

# Check connector health
curl -X POST http://localhost:8000/v1/connectors/<connector_id>/health
```

Configuration
- MCP_API_BACKEND: URL of Phase 1 API to proxy conversions and test-runs to (default: http://host.docker.internal:8000/v1)
- CELERY_BROKER_URL: Redis broker URL (default: redis://redis:6379/0)
- RESULT_BACKEND: Celery result backend (optional)
- DATABASE_URL: PostgreSQL connection string used by API and worker
- POSTGRES_USER / POSTGRES_PASSWORD / POSTGRES_DB: Postgres credentials used by docker-compose

Notes
- This is a minimal scaffold for development and demonstration. Production deployments should use secured secrets, proper deployments, and persistent storage.
- Elasticsearch support remains through Phase 1: `mcp` jobs proxy to Phase 1 `/v1/test-runs`, which runs EQL against Elasticsearch.
