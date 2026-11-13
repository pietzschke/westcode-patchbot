# Allow-listing egress proxy for patchbot-sandbox-egress (built by deploy/compose.yaml).
FROM alpine:3.22
RUN apk add --no-cache squid
COPY squid.conf /etc/squid/squid.conf
USER squid
EXPOSE 3128
CMD ["squid", "-N", "-f", "/etc/squid/squid.conf"]
