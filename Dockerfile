FROM python:3.15-slim AS build
WORKDIR /src
RUN pip install --no-cache-dir build
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m build --wheel --outdir /dist

FROM python:3.15-slim
LABEL org.opencontainers.image.title="sitecheckup" \
      org.opencontainers.image.description="Passive website audit and migration comparison tool" \
      org.opencontainers.image.licenses="MIT"
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
COPY --from=build /dist/*.whl /tmp/
RUN pip install /tmp/*.whl && rm -f /tmp/*.whl \
    && useradd --create-home --uid 10001 sitecheckup
USER sitecheckup
WORKDIR /home/sitecheckup
ENTRYPOINT ["sitecheckup"]
CMD ["--help"]
