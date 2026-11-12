Terminal agent OTA rollout orchestrator

Run all tests:
python3 -m unittest discover -s tests -v

Compile production sources:
python3 -m compileall -q ota_orchestrator

Run the offline acceptance scenario:
python3 -m ota_orchestrator run-fixture fixtures/acceptance.json --database /tmp/ota-orchestrator-acceptance.sqlite3 --output /tmp/ota-orchestrator-acceptance.json

Inspect a persisted release:
python3 -m ota_orchestrator inspect --database /tmp/ota-orchestrator-acceptance.sqlite3 --release release-ota-fixture-002

The fixture contains synthetic devices, signatures, metrics, failures, and receipts. The program uses only the Python standard library and SQLite.
