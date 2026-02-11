FROM python:3.10-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && \
    apt install -y --no-install-recommends \
    iproute2 \
    git

COPY start.sh /start.sh
RUN chmod +x /start.sh
RUN pip install requests

CMD ["/start.sh"]
