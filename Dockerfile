FROM python:3.13-slim

WORKDIR /app

RUN python3 -m ensurepip

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["python", "app.py"]
