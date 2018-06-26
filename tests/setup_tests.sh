#!/bin/sh -xe

# This script starts docker and systemd (if el7)

# Version of CentOS/RHEL
el_version=$1

 # Run tests in Container
if [ "$el_version" = "6" ]; then

    sudo docker run --rm=true \
         --volume `pwd`:/osg-pki-tools:rw \
         centos:centos${OS_VERSION} \
         /bin/bash -c "bash -xe /osg-pki-tools/tests/test_inside_docker.sh ${OS_VERSION}"

elif [ "$el_version" = "7" ]; then

    docker run --detach --tty --interactive --env "container=docker" \
           --volume `pwd`:/osg-pki-tools:rw \
           centos:centos${OS_VERSION} \
           /usr/sbin/init

    DOCKER_CONTAINER_ID=$(docker ps | grep centos | awk '{print $1}')
    docker logs $DOCKER_CONTAINER_ID
    docker exec --tty --interactive $DOCKER_CONTAINER_ID \
           /bin/bash -xec "bash -xe /osg-pki-tools/tests/test_inside_docker.sh ${OS_VERSION};
           echo -ne \"------\nEND OSG-PKI-TOOLS TESTS\n\";"

    docker ps -a
    docker stop $DOCKER_CONTAINER_ID
    docker rm -v $DOCKER_CONTAINER_ID

fi



