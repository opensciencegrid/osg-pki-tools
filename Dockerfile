ARG BASE_OSG_SERIES=3.6
ARG BASE_YUM_REPO=release

FROM opensciencegrid/software-base:$BASE_OSG_SERIES-el8-$BASE_YUM_REPO

LABEL maintainer OSG Software <help@opensciencegrid.org>

COPY . /src

RUN yum update -y && \
    yum install -y python3-m2crypto && \
    yum clean all && \
    rm -rf /var/cache/yum/* && \
    cd /src && \
    python3 setup.py install --root=/
    
WORKDIR /output

ENTRYPOINT ["/usr/local/bin/osg-cert-request"]
