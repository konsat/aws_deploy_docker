FROM python:2.7.15-alpine3.8

WORKDIR /app/wwwroot

COPY requirements.txt /tmp/
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY ./src/. ../
RUN echo success > ./test.html

EXPOSE 8080

CMD [ "python", "../server.py" ]
