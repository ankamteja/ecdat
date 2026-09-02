# Deliberately weak TLS endpoint for demonstrating the ECDAT network scanner.
# See README.md. Not a template for anything.
FROM nginx:1.27-alpine

RUN apk add --no-cache openssl

COPY nginx.conf /etc/nginx/nginx.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
