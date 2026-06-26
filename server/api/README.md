# Sigma UI API

HTTP API for Sigma rule conversion and testing against Elasticsearch.

## Quick Start

### Local Development

1. **Install dependencies:**
   ```bash
   cd server/api
   pip install -r requirements.txt
   ```

2. **Configure environment:**
   ```bash
   cp ../../.env.example .env
   # Edit .env with your Elasticsearch details
   ```

3. **Run the API:**
   ```bash
   python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
   ```

4. **Access API documentation:**
   - Swagger UI: http://localhost:8000/docs
   - ReDoc: http://localhost:8000/redoc

### Docker Compose (Recommended)

Run the full stack (Elasticsearch + Kibana + API) from the project root:

```bash
docker-compose up -d
```

Access:
- **API**: http://localhost:8000
- **Kibana**: http://localhost:5601
- **Elasticsearch**: http://localhost:9200

## API Endpoints

### Health Check
- `GET /health` - Health status
- `GET /health/ready` - Readiness probe (checks Elasticsearch connectivity)

### Conversions
- `POST /v1/conversions` - Convert Sigma rule to EQL/Lucene/ES|QL
  - Request: `{ rule_yaml, format, pipeline }`
  - Response: `{ conversion_id, query_result, format }`

### Test Runs
- `POST /v1/test-runs` - Test a converted rule against live data
  - Request: `{ rule_yaml, index_pattern, timeframe_hours }`
  - Response: `{ test_run_id, hit_count, sample_events, timing_ms }`

## Architecture

```
main.py
  ├── config.py (Settings management)
  ├── middleware/
  │   ├── auth.py (API key validation)
  │   └── errors.py (RFC 7807 error handling)
  ├── routes/
  │   ├── conversions.py (Conversion endpoints)
  │   ├── test_runs.py (Test-running endpoints)
  │   └── health.py (Health checks)
  ├── services/
  │   ├── conversion.py (pySigma wrapper)
  │   └── testing.py (Elasticsearch test execution)
  ├── schemas/
  │   └── models.py (Pydantic models)
  └── tests/
      └── (pytest integration tests)
```

## Authentication

Clients must provide an Elasticsearch API key:

```bash
curl -X POST http://localhost:8000/v1/conversions \
  -H "Authorization: Bearer YOUR_ELASTIC_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "rule_yaml": "title: Test Rule\n...",
    "format": "eql",
    "pipeline": "ecs_windows"
  }'
```

For development, set `ELASTIC_API_KEY` environment variable as a fallback.

## Testing

Run integration tests:

```bash
cd server/api
pytest tests/ -v
```

## Configuration

See `.env.example` for all available settings:
- `ELASTICSEARCH_HOST`, `ELASTICSEARCH_PORT`, `ELASTICSEARCH_SCHEME`
- `CONVERSION_TIMEOUT_SECONDS`
- `TEST_RUN_TIMEOUT_SECONDS`
- `LOG_LEVEL`

## Development Notes

- Pysigma backend uses a subprocess call to the Python converter script
- Field mappings leverage pySigma's built-in ECS pipelines
- Errors follow RFC 7807 (Problem Details) format for consistency
- Logging is JSON-formatted for container log aggregation

## Next Steps

1. Define Pydantic schemas (Phase 1 Step 2)
2. Implement conversion service (Phase 1 Step 3)
3. Implement test-running service (Phase 1 Step 4)
4. Wire routes with services (Phase 1 Step 5)
