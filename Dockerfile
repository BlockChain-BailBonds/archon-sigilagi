FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=7860 NAP_DB_PATH=/data/archon-sigilagi.db
WORKDIR /app
COPY pyproject.toml README.md ./
COPY nap ./nap
COPY schemas ./schemas
COPY policies ./policies
RUN pip install --no-cache-dir .
RUN useradd --create-home --uid 10001 archon && mkdir -p /data && chown -R archon:archon /app /data
USER archon
EXPOSE 7860
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:7860/healthz', timeout=3)"
CMD ["python", "-m", "nap.cli", "serve"]
