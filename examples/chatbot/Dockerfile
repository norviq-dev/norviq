# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
#
# Build from the REPO ROOT — the context needs both norviq/ and examples/chatbot/:
#   docker build -f examples/chatbot/Dockerfile -t norviq-demo-chatbot:dev .
FROM python:3.12-slim

WORKDIR /app

# Install the Norviq SDK from this checkout, with the two framework extras the demo uses. Copying
# only the build inputs first keeps this layer cached across example edits. (Copying norviq/ into
# /app without installing it would leave its own runtime deps -- httpx, structlog, pydantic-settings
# -- missing, and the app would fail on import.)
COPY pyproject.toml README.md ./
COPY norviq/ ./norviq/
RUN pip install --no-cache-dir ".[langchain,langgraph]"

COPY examples/chatbot/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY examples/chatbot/ .

USER 65534
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
