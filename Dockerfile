# The agentsec gateway (`agentsec serve`). Build from the repository root:
#
#   docker build -t agentsec-gateway .
#
# Mount a config directory at /etc/agentsec and a writable volume at /var/lib/agentsec
# (audit log, token store, bundle state). See docs/GATEWAY.md, "Container image".

# Pinned by digest; Dependabot moves it (.github/dependabot.yml).
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS build

ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src

# Dependencies first, from the hash-pinned locks, so this layer is reused until a lock changes.
# The runtime venv has no pip of its own: the build stage's pip installs into it.
COPY requirements/requirements-gateway.txt requirements/requirements-release-tools.txt requirements/
RUN python -m venv --without-pip /opt/agentsec \
    && pip --python /opt/agentsec/bin/python install --require-hashes -r requirements/requirements-gateway.txt \
    && pip install --require-hashes -r requirements/requirements-release-tools.txt

# The wheel is built as the release builds it: backend from the hashed lock, no isolation.
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m build --no-isolation --wheel \
    && pip --python /opt/agentsec/bin/python install --no-deps dist/*.whl


FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

# A fixed numeric id, so `runAsNonRoot` and volume ownership can name it.
# The base image's own pip goes too: nothing is installed at runtime.
RUN python -m pip uninstall --yes --quiet pip \
    && groupadd --system --gid 10001 agentsec \
    && useradd --system --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin agentsec \
    && install -d -o 10001 -g 10001 -m 0700 /var/lib/agentsec

COPY --from=build /opt/agentsec /opt/agentsec

ENV PATH=/opt/agentsec/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER 10001:10001
WORKDIR /etc/agentsec
EXPOSE 8443

# checkov:skip=CKV_DOCKER_2: the port and TLS come from the mounted config, so a baked-in probe would be wrong; probe /healthz from the orchestrator
ENTRYPOINT ["agentsec"]
CMD ["serve", "--config", "/etc/agentsec/gateway.yaml"]
