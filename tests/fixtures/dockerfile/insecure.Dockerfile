FROM nginx:latest
USER root
EXPOSE 22
ENV SECRET_KEY=hardcoded_password123
RUN apt-get update && apt-get install -y vim
