import hashlib
import logging
import os
import zlib

from pygit import utils


LOG = logging.getLogger(__name__)


def init(repo):
    """Create directory for repo and initialize .git directory"""
    os.mkdir(repo)
    os.mkdir(os.path.join(repo, '.git'))
    for name in ['objects', 'refs', 'refs/heads']:
        os.mkdir(os.path.join(repo, '.git', 'name'))
    utils.write_file(os.path.join(repo, '.git', 'HEAD'),
                     b'ref: refs/heads/master')
    LOG.info('Initialized empty repository: {}' . format(repo))


def hash_objects(data, obj_type, write=True):
    """Compute hash of object data of given type and write to object store
    if "write" is True. Return SHA-1 object hash as hex string

    There are 3 types of objects in the Git model:
        * blobs (ordinary files)
        * commits
        * trees (these represent the state of a single directory)
    Each object has a small header including the type and size in bytes.
    """
    header = '{} {}' . format(obj_type, len(data)).encode()
    full_data = header + b'\x00' + data
    sha1 = hashlib.sha1(full_data).hexdigest()
    if write:
        path = os.path.join('.git', 'objects', sha1[:2], sha1[:2])
        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            utils.write_file(path, zlib.compress(full_data))

    return sha1
