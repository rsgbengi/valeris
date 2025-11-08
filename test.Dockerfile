FROM ubuntu:latest

RUN apt-get update && apt-get install -y curl

ENV API_KEY=supersecret123
ENV DB_PASSWORD=admin

EXPOSE 22
EXPOSE 3306

USER root

COPY . /app
WORKDIR /app

CMD ["/bin/bash"]