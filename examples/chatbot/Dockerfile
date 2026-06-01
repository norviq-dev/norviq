# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
FROM python:3.12-slim

WORKDIR /app

COPY examples/chatbot/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY examples/chatbot/ .
COPY norviq/ /app/norviq/

USER 65534
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
