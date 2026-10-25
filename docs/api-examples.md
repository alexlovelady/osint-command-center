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

## 9. Active verification (AIV; off by default)

```bash
curl -s -H "$AUTH" -X PUT $BASE/aiv/settings -H 'Content-Type: application/json' -d '{"enabled":true}'     # admin
curl -s -H "$AUTH" -X POST $BASE/cases/$CASE/asset-authorizations -H 'Content-Type: application/json' -d '{"asset_type":"fqdn","scope":["www.example.org"],"ports":[443],
  "allowed_classes":["http_metadata","tls_handshake"],"authorized_by":"Owner","authority_role":"owner","source_of_authority":"I operate this server","expires_at":"2026-12-01T00:00:00Z"}'
curl -s -H "$AUTH" -X POST $BASE/cases/$CASE/aiv/plans/preview -H 'Content-Type: application/json' -d '{"authorization_id":"<id>","steps":[{"kind":"tls_handshake","host":"www.example.org","port":443}]}'   # sends nothing
curl -s -H "$AUTH" -X POST $BASE/aiv/plans/<plan>/approve -H 'Content-Type: application/json' -d '{"confirm":true,"expires_in_minutes":30}'
curl -s -H "$AUTH" -X POST $BASE/aiv/plans/<plan>/run -H 'Content-Type: application/json' -d '{"approval_id":"<approval>"}'
```

## 10. DARKINT (exposure intelligence)

```bash
curl -s -H "$AUTH" $BASE/darkint/sources                                                                      # one honest state per provider
curl -s -H "$AUTH" -X POST $BASE/cases/$CASE/darkint/preview -H 'Content-Type: application/json' -d '{"subject_id":"<s>","identifier_ids":["<i>"],"provider_ids":["hibp"]}'   # sends nothing
curl -s -H "$AUTH" -X POST $BASE/cases/$CASE/darkint/check -H 'Content-Type: application/json' -d '{"subject_id":"<s>","identifier_ids":["<i>"],"provider_ids":["hibp"],"confirm":true}'
curl -s -H "$AUTH" "$BASE/cases/$CASE/darkint/exposures?subject_id=<s>"                                        # coverage, grouped incidents, reviews
```
