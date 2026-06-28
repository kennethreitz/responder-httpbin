# syntax=docker/dockerfile:1
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

LABEL name="responder-httpbin"
LABEL description="The httpbin API, powered by the responder web framework."
LABEL org.kennethreitz.vendor="Kenneth Reitz"

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENV PYTHONUNBUFFERED=1
# uv: copy installed packages (no hardlinks across layers) and compile bytecode.
ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy

WORKDIR /app

# Install dependencies first, in their own cached layer (no project code yet).
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-dev

# Install the application itself.
COPY . /app
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev

# Run the project's virtualenv binaries directly.
ENV PATH="/app/.venv/bin:$PATH"

EXPOSE 80

# Granian (Rust HTTP server) serving the responder ASGI app.
CMD ["granian", "--interface", "asgi", "--host", "0.0.0.0", "--port", "80", "httpbin:api"]
