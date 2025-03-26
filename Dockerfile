ARG BASE_OSG_SERIES=24
ARG BASE_YUM_REPO=release

FROM opensciencegrid/software-base:$BASE_OSG_SERIES-el9-$BASE_YUM_REPO

LABEL maintainer OSG Software <help@opensciencegrid.org>

COPY . /src

RUN yum update -y && \
    yum install -y python3-pip python3-m2crypto && \
    yum clean all && \
    rm -rf /var/cache/yum/* && \
    cd /src && \
    pip3 install -r requirements.txt && \
    python3 setup.py install --root=/ && \
    mkdir -p /etc/osg/pki && \
    cp /usr/local/config/ca-issuer.conf /etc/osg/pki/

WORKDIR /output

ENTRYPOINT ["/usr/local/bin/osg-cert-request"]
