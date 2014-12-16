"""
Install Python, Ruby, and Node prerequisites.
"""

import os
import hashlib
from distutils import sysconfig
from paver.easy import *
from .utils.envs import Env
from .utils.prereqs import PyVenvStore


PREREQS_MD5_DIR = os.getenv('PREREQ_CACHE_DIR', Env.REPO_ROOT / '.prereqs_cache')
NPM_REGISTRY = "http://registry.npmjs.org/"
PYTHON_REQ_FILES = [
    'requirements/edx/pre.txt',
    'requirements/edx/github.txt',
    'requirements/edx/local.txt',
    'requirements/edx/base.txt',
    'requirements/edx/post.txt',
]

# Developers can have private requirements, for local copies of github repos,
# or favorite debugging tools, etc.
PRIVATE_REQS = 'requirements/private.txt'
if os.path.exists(PRIVATE_REQS):
    PYTHON_REQ_FILES.append(PRIVATE_REQS)


def no_prereq_install():
    """
    Determine if NO_PREREQ_INSTALL should be truthy or falsy.
    """
    vals = {
        '0': False,
        '1': True,
        'true': True,
        'false': False,
    }

    val = os.environ.get("NO_PREREQ_INSTALL", 'False').lower()

    try:
        return vals[val]
    except:
        return False


def compute_fingerprint(path_list):
    """
    Hash the contents of all the files and directories in `path_list`.
    Returns the hex digest.
    """

    hasher = hashlib.sha1()

    for path in path_list:

        # For directories, create a hash based on the modification times
        # of first-level subdirectories
        if os.path.isdir(path):
            for dirname in sorted(os.listdir(path)):
                p = os.path.join(path, dirname)
                if os.path.isdir(p):
                    hasher.update(str(os.stat(p).st_mtime))

        # For files, hash the contents of the file
        if os.path.isfile(path):
            with open(path, "rb") as file_handle:
                hasher.update(file_handle.read())

    return hasher.hexdigest()


def prereq_cache(cache_name, paths, install_func):
    """
    Conditionally execute `install_func()` only if the files/directories
    specified by `paths` have changed.

    If the code executes successfully (no exceptions are thrown), the cache
    is updated with the new hash.
    """
    # Retrieve the old hash
    cache_filename = cache_name.replace(" ", "_")
    cache_file_path = os.path.join(PREREQS_MD5_DIR, "{}.sha1".format(cache_filename))
    old_hash = None
    if os.path.isfile(cache_file_path):
        with open(cache_file_path) as cache_file:
            old_hash = cache_file.read()

    # Compare the old hash to the new hash
    # If they do not match (either the cache hasn't been created, or the files have changed),
    # then execute the code within the block.
    new_hash = compute_fingerprint(paths)
    if new_hash != old_hash:
        install_func()

        # Update the cache with the new hash
        # If the code executed within the context fails (throws an exception),
        # then this step won't get executed.
        try:
            os.makedirs(PREREQS_MD5_DIR)
        except OSError:
            if not os.path.isdir(PREREQS_MD5_DIR):
                raise

        with open(cache_file_path, "w") as cache_file:
            # Since we are using sysconfig.get_python_lib() to generate the hash in
            # addition to the requirements files and those files are modified during
            # the installation process, we need to store a hash that is computed
            # AFTER the installation is done. 
            # TODO: check on why we are using sysconfig.get_python_lib() for computing
            # the python requirements hash and remove it if we can.
            post_install_hash = compute_fingerprint(paths)
            cache_file.write(post_install_hash)
    else:
        print('{cache} unchanged, skipping...'.format(cache=cache_name))


def ruby_prereqs_installation():
    """
    Installs Ruby prereqs
    """
    sh('bundle install --quiet')


def node_prereqs_installation():
    """
    Configures npm and installs Node prerequisites
    """
    sh("test `npm config get registry` = \"{reg}\" || "
       "(echo setting registry; npm config set registry"
       " {reg})".format(reg=NPM_REGISTRY))
    sh('npm install')


def python_prereqs_installation():
    """
    Installs Python prerequisites
    """
    for req_file in PYTHON_REQ_FILES:
        sh("pip install -q --exists-action w -r {req_file}".format(req_file=req_file))


def jenkins_python_prereqs_installation():
    """
    Installs python prereqs on a jenkins worker.
    """
    # TODO: add some exception handling here.
    req_hash = compute_fingerprint(PYTHON_REQ_FILES)
    store = PyVenvStore(req_hash)

    if store.key:
        store.extract()
    else:
        python_prereqs_installation()
        store.upload()


@task
def install_jenkins_python_prereqs():
    """
    Installs python prerequisites on a jenkins worker.
    This is optimized for speed by trying to use a prebuilt
    virtual env stored in S3 that matches these requirements.
    """
    # Note: We still need to use sysconfig.get_python_lib()
    # here so that install_python_prereqs will have a matching
    # hash when it is run in jenkins.
    prereq_cache(
        "Python prereqs",
        PYTHON_REQ_FILES + [sysconfig.get_python_lib()],
        jenkins_python_prereqs_installation
    )


@task
def install_ruby_prereqs():
    """
    Installs Ruby prereqs
    """
    if no_prereq_install():
        return

    prereq_cache("Ruby prereqs", ["Gemfile"], ruby_prereqs_installation)


@task
def install_node_prereqs():
    """
    Installs Node prerequisites
    """
    if no_prereq_install():
        return

    prereq_cache("Node prereqs", ["package.json"], node_prereqs_installation)


@task
def install_python_prereqs():
    """
    Installs Python prerequisites
    """
    if no_prereq_install():
        return

    prereq_cache("Python prereqs", PYTHON_REQ_FILES + [sysconfig.get_python_lib()], python_prereqs_installation)


@task
def install_prereqs():
    """
    Installs Ruby, Node and Python prerequisites
    """
    if no_prereq_install():
        return

    install_ruby_prereqs()
    install_node_prereqs()
    install_python_prereqs()
