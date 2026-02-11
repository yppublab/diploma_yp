FROM node:20-alpine

RUN apk add --no-cache git python3 make g++

WORKDIR /app
RUN git clone --depth 1 https://github.com/xeokit/xeokit-bim-viewer . \
    && rm -rf .git \
    && npm install --no-audit --no-fund \
    && npm run build
COPY index.html /app/index.html


EXPOSE 8080
CMD ["sh", "-lc", "npm run serve"]
