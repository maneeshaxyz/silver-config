FROM python:3.11-slim

WORKDIR /app

COPY exporter.py /app/

RUN chmod +x /app/exporter.py

EXPOSE 9810

CMD ["python3", "/app/exporter.py"]
