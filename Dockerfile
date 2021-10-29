FROM python:3.8.5-alpine3.12

RUN apk add build-base
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY sync.py .

CMD python -u sync.py
