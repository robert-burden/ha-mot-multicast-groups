ARG BUILD_FROM
FROM $BUILD_FROM

WORKDIR /usr/src/app
COPY server.py ./
COPY run.sh /
RUN chmod a+x /run.sh

CMD ["/run.sh"]
