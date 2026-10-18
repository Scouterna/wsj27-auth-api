# Use a slim Python image for the application. The official image, copied into
# this repo's own GHCR package by the build workflow: Docker Hub and AWS's
# public mirror both rate-limit the anonymous pulls CI makes (429). Change the
# tag in both places.
FROM ghcr.io/scouterna/wsj27-auth-api/python:3.14-slim

# Install uv as the package manager
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Set timezone to local for log improvements
ENV TZ="Europe/Stockholm"

# Ensures Python's stdout/stderr goes directly to the container logs unbuffered
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies first so this layer caches independently of the source
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev
ENV PATH="/app/.venv/bin:$PATH"

# Application source and the client-side refresh script
COPY src/ ./src
COPY static/ ./static
ENV PYTHONPATH=/app/src

# Run as a non-root user: this service holds the signing key in memory.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app \
    && chown -R app:app /app
USER app

EXPOSE 8000

# start.py resolves .env relative to the working directory. There is no .env in
# the image by design — configuration comes from the k8s ConfigMap and Secret.
WORKDIR /app/src
CMD ["python", "start.py"]
