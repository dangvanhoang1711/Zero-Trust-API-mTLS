FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY routes/ ./routes/
COPY services/ ./services/
COPY requirements.txt .

EXPOSE 8080

CMD ["python3", "-m", "gunicorn", "-w", "4", "-b", "0.0.0.0:8080", "app:create_app()"]
