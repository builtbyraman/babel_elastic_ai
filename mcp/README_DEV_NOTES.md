Dev notes

- To run locally using the Phase 1 API running on your host, set `MCP_API_BACKEND` in `.env` to `http://host.docker.internal:8000/v1` (Docker Desktop on macOS/Windows).
- If Phase 1 API runs in Docker Compose, update networking accordingly.
- The stack now includes PostgreSQL for job metadata and connector definitions.

Commands:

```bash
cd mcp
cp .env.example .env
docker-compose up --build
```

Submit conversion job (async):
```bash
curl -X POST http://localhost:8000/v1/conversions -H "Content-Type: application/json" -d '{"rule_yaml":"title: Test\ndetection:\n  selection:\n    Image: test.exe\n  condition: selection","format":"eql","pipeline":"ecs_windows"}'
```

Submit Elasticsearch test-run job (async):
```bash
curl -X POST http://localhost:8000/v1/test-runs -H "Content-Type: application/json" -d '{"rule_yaml":"title: Test\ndetection:\n  selection:\n    Image: test.exe\n  condition: selection","index_pattern":"*","timeframe_hours":24}'
```

Query job status:
```bash
curl http://localhost:8000/v1/jobs/<job_id>
```

Submit sync conversion (proxy to Phase1):
```bash
curl -X POST http://localhost:8000/v1/conversions/sync -H "Content-Type: application/json" -d '{"rule_yaml":"title: Test\n..."}'
```
