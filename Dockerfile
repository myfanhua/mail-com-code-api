FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY server.py mailcom_client.py code_extract.py storage.py ./
COPY web ./web
RUN useradd --system --uid 10001 --create-home app && mkdir /data && chown app:app /data
USER app
VOLUME ["/data"]
EXPOSE 8988
CMD ["python", "server.py", "--bind", "0.0.0.0", "--port", "8988", "--data-dir", "/data"]
