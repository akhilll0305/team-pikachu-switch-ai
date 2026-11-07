# The sandbox for the sqlparse target. Same shape as target/Dockerfile: one
# image per pinned version of the library, no network at run time, dependencies
# installed at build time and pinned by SHA-256.
#
#   docker build --build-arg SQLPARSE_VERSION=0.4.3 -t proveit-target-sqlparse:vulnerable target-sqlparse/
#   docker build --build-arg SQLPARSE_VERSION=0.4.4 -t proveit-target-sqlparse:patched    target-sqlparse/
#
# Built only on request (`python -m proveit build --target sqlparse`); it is not
# built by a bare `proveit build`, and the test suite never builds it.
#
# Same pinned base image as PyYAML, so the two targets share a Python runtime
# and an unprivileged user. sqlparse is pure Python, so there is nothing to
# compile; the wheel is checked against its index SHA-256 (hashes.txt).
FROM python:3.9-slim@sha256:2d97f6910b16bd338d3060f261f53f144965f755599aab1acda1e13cf1731b1b

ARG SQLPARSE_VERSION
COPY hashes.txt /tmp/hashes.txt
# Build the pinned requirement line from hashes.txt for the requested version,
# then install with --require-hashes so a wrong download fails the build.
RUN test -n "$SQLPARSE_VERSION" \
    && HASH="$(awk -v v="$SQLPARSE_VERSION" '$1==v {print $2}' /tmp/hashes.txt)" \
    && test -n "$HASH" \
    && printf 'sqlparse==%s --hash=sha256:%s\n' "$SQLPARSE_VERSION" "$HASH" > /tmp/req.txt \
    && pip install --no-cache-dir --disable-pip-version-check --require-hashes -r /tmp/req.txt \
    && python -c "import sqlparse; print('sqlparse', sqlparse.__version__)"

COPY harness.py child.py /harness/

# Never run a stranger's input as root.
USER 65534:65534
WORKDIR /tmp
ENTRYPOINT ["python", "-I", "/harness/harness.py"]
