# ECDAT backend image.
#
# Runs as a non-root user with the application tree owned by root, so the
# process can read its own code but cannot rewrite it. Only the data and report
# directories are writable.
#
# System packages are needed for WeasyPrint (pango, cairo, gdk-pixbuf) and for
# openssl, which the sample certificate generator shells out to for the SHA-1
# signed certificate that the cryptography library correctly refuses to produce.

FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# WeasyPrint's rendering stack plus openssl. Pinned to the slim base's
# repository versions; there is no network access at runtime.
RUN apt-get update && apt-get install --no-install-recommends -y \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libcairo2 \
        libgdk-pixbuf-2.0-0 \
        libffi8 \
        shared-mime-info \
        fonts-dejavu-core \
        openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/
COPY schemas/ ./schemas/
COPY samples/ ./samples/
COPY pytest.ini ./

# The application tree stays owned by root and is only readable by the runtime
# user. A scanner that reads untrusted repositories should not be able to
# modify its own rules or code.
RUN useradd --create-home --shell /usr/sbin/nologin --uid 10001 ecdat \
    && mkdir -p /app/data /app/reports_out \
    && chown -R ecdat:ecdat /app/data /app/reports_out \
    && chmod -R a-w /app/backend /app/schemas

USER ecdat

ENV ECDAT_DATABASE_URL=sqlite:////app/data/ecdat.db \
    PYTHONPATH=/app/backend

EXPOSE 8000

# Kept in the image so `docker compose exec` can confirm the service is healthy
# without needing curl on the host.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=3).status == 200 else 1)"

WORKDIR /app/backend
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
