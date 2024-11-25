FROM python:3.9-slim

WORKDIR /usr/src/app
COPY requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "app.py"]

# docker build -t anonymizer-ae .
# OR  docker build --no-cache -t anonymizer-ae .

# docker run -it --rm --network thoth anonymizer-ae