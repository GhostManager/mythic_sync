FROM python:3.8-slim

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY sync.py .

CMD python -u sync.py
