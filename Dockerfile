FROM redis:7-bullseye

RUN apt update && apt install python3 python3-pip -y  \
    --no-install-recommends

COPY requirements.txt .
RUN python3 -m pip install -r requirements.txt

COPY sync.py .

CMD ["bash", "-c", "redis-server &  python3 -u sync.py"]
