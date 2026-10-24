# API examples

Reference: `docs/api.md` (generated), live docs at `/api/docs`. Every example below is replayed by
`tests/integration/test_api_examples.py`, so the paths and fields cannot silently rot.

Set the base and token (the dev launcher prints them; the packaged app gives them only to its own window):

```bash
BASE=http://127.0.0.1:8791/api/v1
AUTH="Authorization: Bearer dev-token-local-only"
```

## 1. Create a case

```bash
curl -s -H "$AUTH" -H 'Content-Type: application/json' -X POST $BASE/cases \
  -d '{"title":"Acme domain review","category":"cyber","purpose":"verify we own acme.example"}'
# -> {"id": "<case>", "status": "active", ...}
```

## 2. Preview, then run (nothing is contacted by the preview)

```bash
curl -s -H "$AUTH" -H 'Content-Type: application/json' -X POST $BASE/cases/$CASE/searches/preview -d '{"target":"example.com"}'
# steps[] lists each source, what it will contact, and whether policy allows it
curl -s -H "$AUTH" -H 'Content-Type: application/json' -X POST $BASE/cases/$CASE/searches \
  -d '{"target":"example.com","adapters":["rdap","dns"],"wait":true}'
# -> {"id": "<run>", "status": "succeeded"|"partial", "jobs": [...]}
```

## 3. Read findings with their evidence

```bash
curl -s -H "$AUTH" "$BASE/cases/$CASE/findings?limit=50"
curl -s -H "$AUTH" $BASE/cases/$CASE/evidence      # sha256, size, retrieved_at
```

## 4. Promote a finding to a claim, then mark it yourself

```bash
curl -s -H "$AUTH" -H 'Content-Type: application/json' -X POST $BASE/claims/from-finding -d '{"finding_id":"<finding>"}'
curl -s -H "$AUTH" -H 'Content-Type: application/json' -X POST $BASE/claims/<claim>/verification -d '{"status":"analyst_verified"}'
```

## 5. Import a file you own (nothing is executed)

```bash
curl -s -H "$AUTH" -X POST "$BASE/cases/$CASE/ingest?filename=photo.jpg&consent_confirmed=true" --data-binary @photo.jpg
```

## 6. Cross-discipline suggestions (suggestions only)

```bash
curl -s -H "$AUTH" "$BASE/cases/$CASE/cross-links?window_s=300&radius_m=1000&include_restricted=true"
curl -s -H "$AUTH" -H 'Content-Type: application/json' -X POST $BASE/cases/$CASE/cross-links/decision \
  -d '{"obs_a":"<id>","obs_b":"<id>","kind":"both","decision":"accept","note":"same scene"}'
curl -s -H "$AUTH" -X POST $BASE/correlations/<correlation>/revoke
curl -s -H "$AUTH" "$BASE/cases/$CASE/timeline/unified?include_restricted=true"
```

## 7. Report: preview what leaves, then generate

```bash
curl -s -H "$AUTH" -H 'Content-Type: application/json' -X POST $BASE/cases/$CASE/reports/preview -d '{"profile":"multi_int"}'
curl -s -H "$AUTH" -H 'Content-Type: application/json' -X POST $BASE/cases/$CASE/reports -d '{"profile":"multi_int","format":"html"}'
curl -s -H "$AUTH" -o report.html $BASE/reports/<report>/download
```

## 8. Backup (admin)

```bash
curl -s -H "$AUTH" -H 'Content-Type: application/json' -X POST $BASE/backups -d '{"passphrase":"a long passphrase"}'
curl -s -H "$AUTH" -H 'Content-Type: application/json' -X POST $BASE/backups/verify -d '{"file":"<name>.zip.enc","passphrase":"a long passphrase"}'
```

## Error shape

```json
{"code":"not_found","message":"…","request_id":"…","retryable":false,"details_safe":{}}
```
