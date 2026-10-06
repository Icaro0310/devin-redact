FROM gcr.io/oss-fuzz-base/base-builder-python:v1
COPY . $SRC/devin-redact
WORKDIR devin-redact
COPY .clusterfuzzlite/build.sh $SRC/build.sh
