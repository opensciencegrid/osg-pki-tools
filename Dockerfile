FROM opensciencegrid/software-base:3.6-el8-release

LABEL maintainer OSG Software <help@opensciencegrid.org>

COPY . /src

RUN yum update -y && \
    yum install -y python3-m2crypto && \
    yum clean all && \
    rm -rf /var/cache/yum/* && \
    cd /src && \
    python3 setup.py install --root=/

ENTRYPOINT ["/usr/local/bin/osg-cert-request"]
