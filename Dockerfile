# Two stages so build tooling and caches never reach the runtime image.
FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Dependencies are installed before the source is copied, so a code change
# does not invalidate the dependency layer.
COPY requirements.txt ./
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN /opt/venv/bin/pip install --no-cache-dir --no-deps .

# The retrieval index is built here, at image build time. Embedding the
# control catalogue takes around two minutes, which no reader should wait for,
# and baking it in means the running service needs no network at all.
COPY data/ ./data/
COPY scripts/ ./scripts/
ENV PYTHONPATH=/build/src \
    FASTEMBED_CACHE_PATH=/opt/models
RUN /opt/venv/bin/python scripts/fetch_reference_data.py --verify \
    && /opt/venv/bin/python scripts/build_index.py \
    && /opt/venv/bin/python scripts/build_index.py --verify


FROM python:3.12-slim AS runtime

# A non-root user with no shell: nothing in the container needs to log in.
RUN groupadd --system --gid 1001 app \
    && useradd --system --uid 1001 --gid app --no-create-home --shell /usr/sbin/nologin app

# Data locations are absolute. The package is installed into the environment
# rather than run from the source tree, so a path derived from the source
# layout does not resolve here.
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    APP_ENV=production \
    FASTEMBED_CACHE_PATH=/opt/models \
    DATA_RAW_DIR=/app/data/raw \
    DATA_REFERENCE_DIR=/app/data/reference \
    DATA_OUTPUT_DIR=/app/data/outputs \
    VECTOR_INDEX_PATH=/app/data/processed/nist_index

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /opt/models /opt/models
COPY --from=builder --chown=app:app /build/data/raw /app/data/raw
COPY --from=builder --chown=app:app /build/data/reference /app/data/reference
COPY --from=builder --chown=app:app /build/data/processed /app/data/processed
COPY --chown=app:app main.py ./

USER app

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).status == 200 else 1)"

# Shell form so the platform-provided PORT is honoured where one is set.
CMD exec uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}
