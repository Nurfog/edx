FROM ubuntu:xenial as base

# Warning: This file is experimental.

# Install system requirements
RUN apt update && \
    # Global requirements
    DEBIAN_FRONTEND=noninteractive apt-get install --yes \
    build-essential \
    curl \
    # If we don't need gcc, we should remove it.
    g++ \
    gcc \
    git \
    git-core \
    language-pack-en \
    libfreetype6-dev \
    libmysqlclient-dev \
    libssl-dev \
    libxml2-dev \
    libxmlsec1-dev \
    libxslt1-dev \
    software-properties-common \
    swig \
    # openedx requirements
    gettext \
    gfortran \
    graphviz \
    libffi-dev \
    libfreetype6-dev \
    libgeos-dev \
    libgraphviz-dev \
    libjpeg8-dev \
    liblapack-dev \
    libpng-dev \
    libsqlite3-dev \
    libxml2-dev \
    libxmlsec1-dev \
    libxslt1-dev \
    ntp \
    pkg-config \
    python3-dev \
    python3-pip \
    python3.5 \
    rm -rf /var/lib/apt/lists/*

RUN locale-gen en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

RUN ln -s /usr/bin/pip3 /usr/bin/pip
RUN ln -s /usr/bin/python3 /usr/bin/python

WORKDIR /edx/app/edx-platform/edx-platform

ENV PATH /edx/app/edx-platform/nodeenv/bin:${PATH}
ENV PATH ./node_modules/.bin:${PATH}
ENV CONFIG_ROOT /edx/etc/
ENV PATH /edx/app/edx-platform/edx-platform/bin:${PATH}
ENV SETTINGS production
RUN mkdir -p /edx/etc/

# Distinguish requirements that come from code within edx-platform
# from external requirements (specifically, those from pip or GitHub).
# Then, install just external requirements.
# This way, the cached installations of external requirements are not
# busted whenever edx-platform code is changed.
# TODO this is quite a hack and should be done in `make upgrade` probably.
RUN pip install setuptools==39.0.1 pip==9.0.3
COPY requirements/ requirements/
RUN grep -E    "^-e (common|openedx|lms|cms|\.)(/| )" requirements/edx/base.txt > requirements/edx/base_in_tree.txt
RUN grep -E -v "^-e (common|openedx|lms|cms|\.)(/| )" requirements/edx/base.txt > requirements/edx/base_not_in_tree.txt
RUN pip install -r requirements/edx/base_not_in_tree.txt

# Copy just JS requirements and install them.
COPY package.json package.json
COPY package-lock.json package-lock.json
# TODO: Shouldn't we use node==12.11.1?
RUN nodeenv /edx/app/edx-platform/nodeenv --node=8.9.3 --prebuilt
RUN npm set progress=false && npm install

# Install remaining requirements -- that is, the in-tree ones.
COPY setup.py setup.py
COPY common common
COPY openedx openedx
COPY lms lms
COPY cms cms
RUN pip install -r requirements/edx/base_in_tree.txt

ENV LMS_CFG /edx/etc/lms.yml
ENV STUDIO_CFG /edx/etc/studio.yml
COPY lms/devstack.yml /edx/etc/lms.yml
COPY cms/devstack.yml /edx/etc/studio.yml

# Copy over remaining code.
# We do this as late as possible so that small changes to the repo don't bust
# the requirements cache.
COPY . .

EXPOSE 18000

FROM base as lms
ENV SERVICE_VARIANT lms
ENV DJANGO_SETTINGS_MODULE lms.envs.production
CMD gunicorn -c /edx/app/edx-platform/edx-platform/lms/docker_lms_gunicorn.py --name lms --bind=0.0.0.0:18000 --max-requests=1000 --access-logfile - lms.wsgi:application

FROM lms as lms-newrelic
RUN pip install newrelic
CMD newrelic-admin run-program gunicorn -c /edx/app/edx-platform/edx-platform/lms/docker_lms_gunicorn.py --name lms --bind=0.0.0.0:8000 --max-requests=1000 --access-logfile - lms.wsgi:application

FROM lms as lms-devstack
# TODO: This compiles static assets.
# However, it's a bit of a hack, it's slow, and it's inefficient because makes the final Docker cache layer very large.
# We ought to be able to this higher up in the Dockerfile, and do it the same for Prod and Devstack.
RUN mkdir -p test_root/log
ENV DJANGO_SETTINGS_MODULE ""
RUN NO_PREREQ_INSTALL=1 paver update_assets lms --settings devstack_decentralized
ENV DJANGO_SETTINGS_MODULE lms.envs.devstack_decentralized

FROM base as studio
ENV SERVICE_VARIANT cms
ENV DJANGO_SETTINGS_MODULE cms.envs.production
CMD gunicorn -c /edx/app/edx-platform/edx-platform/cms/docker_cms_gunicorn.py --name cms --bind=0.0.0.0:8000 --max-requests=1000 --access-logfile - cms.wsgi:application

FROM studio as studio-newrelic
RUN pip install newrelic
CMD newrelic-admin run-program gunicorn -c /edx/app/edx-platform/edx-platform/cms/docker_cms_gunicorn.py --name cms --bind=0.0.0.0:8000 --max-requests=1000 --access-logfile - cms.wsgi:application

FROM studio as studio-devstack
# TODO: This compiles static assets.
# However, it's a bit of a hack, it's slow, and it's inefficient because makes the final Docker cache layer very large.
# We ought to be able to this higher up in the Dockerfile, and do it the same for Prod and Devstack.
RUN mkdir -p test_root/log
ENV DJANGO_SETTINGS_MODULE ""
RUN NO_PREREQ_INSTALL=1 paver update_assets cms --settings devstack_decentralized
ENV DJANGO_SETTINGS_MODULE cms.envs.devstack_decentralized
