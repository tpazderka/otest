FROM python:3.5.2
MAINTAINER Roland Hedberg <roland@catalogix.se>

RUN pip install --upgrade pip
RUN mkdir /opt/rohe && \
    cd /opt/rohe && \
    mkdir src && \
    cd src  && \
    git clone https://github.com/rohe/pyjwkest.git  && \
    cd pyjwkest && \
    python setup.py install && \
    cd .. && \
    git clone https://github.com/rohe/pyoidc.git && \
    cd pyoidc && \
    python setup.py install && \
    cd .. && \
    git clone https://github.com/rohe/otest.git && \
    cd otest && \
    python setup.py install
