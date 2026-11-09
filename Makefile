run:
	API_KEY=dev-key DATA_DIR=./data flask --app "adversarylab.server:create_app" run --port 8081
test:
	python -m pytest --cov=adversarylab --cov-report=term-missing
lint:
	ruff check .
docker:
	docker compose up --build
screenshots:
	python scripts/capture_screenshots.py
