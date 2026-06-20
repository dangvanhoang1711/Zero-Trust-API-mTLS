FROM python:3.12-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

FROM python:3.12-slim
WORKDIR /app
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH
COPY app/ ./app/
COPY routes/ ./routes/
COPY services/ ./services/
COPY config/ ./config/
EXPOSE 8443
CMD ["python3", "-m", "gunicorn", "-w", "4", "-b", "0.0.0.0:8443", "--certfile=/certs/tls.crt", "--keyfile=/certs/tls.key", "app:create_app()"]
