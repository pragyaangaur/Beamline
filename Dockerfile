# The live beacon.
#
# One process, one machine. That is a correctness requirement, not a cost saving:
# the pulse chain is single-writer (round N+1 links to N, and two emitters would
# fork it), and the token buckets in ratelimit.py are in-process. Scaling this
# horizontally without moving the chain to a single writer and the buckets to Redis
# would produce a beacon that contradicts itself, which is worse than no beacon.

FROM python:3.13-slim AS build
WORKDIR /src

# Dependency layer first, so editing source does not reinstall cryptography.
COPY pyproject.toml README.md ./
COPY beamline ./beamline
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.13-slim
WORKDIR /app

# Runs unprivileged. The volume is chowned in the entrypoint rather than here,
# because Fly attaches it after the image is built.
RUN useradd --system --create-home --uid 10001 beamline

COPY --from=build /install /usr/local
COPY beamline ./beamline
COPY pyproject.toml ./

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    BEAMLINE_HOST=0.0.0.0 \
    BEAMLINE_PORT=8080 \
    BEAMLINE_DB=/data/beamline.db \
    BEAMLINE_POOL_DIR=/data/pool \
    BEAMLINE_SEED_POOL=/data/anu_seed_pool.txt

EXPOSE 8080
VOLUME ["/data"]

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

# One worker, explicitly. uvicorn's default is one, but a future reader reaching for
# --workers should find the reason it is not there written down next to it: every
# worker would run its own pulse loop against the same SQLite file and fork the chain.
CMD ["uvicorn", "beamline.api.app:app", "--host", "0.0.0.0", "--port", "8080", \
     "--workers", "1", "--no-access-log"]
