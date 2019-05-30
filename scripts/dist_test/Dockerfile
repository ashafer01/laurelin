FROM ubuntu:18.04

RUN mkdir /tmp/tests \
 && apt-get -y update \
 && apt-get -y install python3 python3-pip \
 && pip3 install nose

COPY dist/* /tmp/
COPY tests /tmp/tests/
