FROM python:3.9-slim

WORKDIR /usr/src/app
COPY requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt
RUN pip install https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-3.7.1/en_core_web_lg-3.7.1-py3-none-any.whl

COPY . .

CMD ["python", "app.py"]

# docker build -t anonymizer-nlp .
# OR  docker build --no-cache -t anonymizer-nlp .

# docker run -it --rm --network thoth anonymizer-nlp