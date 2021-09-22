FROM opensciencegrid/software-base:3.6-el7-release

LABEL maintainer OSG Software <help@opensciencegrid.org>

COPY . /src

RUN yum update -y && \
    yum install -y python3 && \
    yum install -y python36-m2crypto.x86_64 && \
    yum clean all && \
    rm -rf /var/cache/yum/* && \
    cd /src && \
    python3 setup.py install --root=/

ENTRYPOINT ["/src/osgpkitools/osg-cert-request"]
