FROM nginx:1.20-alpine
RUN apk add --no-cache curl
USER nobody
EXPOSE 8080
