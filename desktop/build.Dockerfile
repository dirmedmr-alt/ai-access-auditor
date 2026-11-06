# Build environment for the Linux app (used by ../build-linux.sh). fpm comes from Ruby because the copy
# electron-builder downloads only runs on x86-64.
FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ruby ruby-dev build-essential xz-utils ca-certificates \
 && gem install --no-document fpm && rm -rf /var/lib/apt/lists/*
