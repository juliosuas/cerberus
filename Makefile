.PHONY: install run test lint seed clean docker-up docker-down

install:
	pip install -r requirements.txt

run:
	python -m api.server

test:
	python -m pytest tests/ -v

lint:
	python -m py_compile core/scanner.py
	python -m py_compile core/monitor.py
	python -m py_compile core/compliance.py
	python -m py_compile api/server.py

seed:
	python -m seed.seed_data

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; true
	rm -f cerberus.db

docker-up:
	docker-compose up -d --build

docker-down:
	docker-compose down
