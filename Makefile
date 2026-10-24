.PHONY: sync test lint typecheck web-test web-build e2e check doctor smoke desktop desktop-test sidecar sidecar-smoke release audit docs bench

sync:
	uv sync --locked
	pnpm --dir apps/web install --frozen-lockfile
lint:
	uv run ruff check backend tests scripts
typecheck:
	uv run mypy
test:
	uv run pytest -q
web-test:
	pnpm --dir apps/web typecheck
	pnpm --dir apps/web lint
	pnpm --dir apps/web test
web-build:
	pnpm --dir apps/web build
e2e:  # uses the system Microsoft Edge and a mocked network
	pnpm --dir apps/web e2e
check: lint typecheck test web-test web-build e2e desktop-test
doctor:
	uv run python -m osintcc.doctor
smoke:  # opt-in, low volume live passive lookup of an IANA-reserved domain
	uv run python scripts/live_smoke.py example.com

desktop:
	pnpm --dir apps/web build
	cargo run --manifest-path apps/desktop/src-tauri/Cargo.toml
desktop-test:
	cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml

sidecar:
	uv run python scripts/build_sidecar.py
sidecar-smoke:
	uv run python scripts/sidecar_smoke.py
release: sidecar web-build
	cd apps/desktop && ../web/node_modules/.bin/tauri build --no-bundle
	uv run python scripts/release.py

audit:  # point-in-time dependency, licence and secret checks
	mkdir -p build
	uv export --no-dev --no-hashes --format requirements-txt -o build/req.txt
	uv tool run pip-audit -r build/req.txt --no-deps --disable-pip
	pnpm --dir apps/web audit
	cd apps/desktop/src-tauri && cargo audit
	uv run python scripts/license_audit.py
	uv run python scripts/secret_scan.py --dist
docs:
	uv run python scripts/gen_docs.py
bench:
	uv run python scripts/benchmarks.py
