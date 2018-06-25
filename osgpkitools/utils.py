from __future__ import print_function

import errno
import os
import shutil
import tempfile

VERSION_NUMBER = "2.1.4"
HELP_EMAIL = 'help@opensciencegrid.org'


def find_existing_file_count(filename):
    '''Check if filename and revisions of the filename exists. If so, increment the revision number and return
    the latest revision filename'''
    temp_name = filename.split(".")[-2]
    trimmed_name = temp_name
    version_count = 0
    if os.path.exists(filename):
        while os.path.exists(temp_name + '.pem'):
            if version_count == 0:
                temp_name = temp_name + '-'+str(version_count)
            else:
                temp_name = trimmed_name
                temp_name = temp_name + '-' + str(version_count)
            version_count = version_count + 1

    if version_count > 0:
        version_count -= 1
        new_file = trimmed_name + '-' + str(version_count) + '.pem'
        return new_file
    return filename


def atomic_write(filename, contents):
    """Write to a temporary file then move it to its final location
    """
    temp_file = tempfile.NamedTemporaryFile(dir=os.path.dirname(filename))
    temp_file.write(contents)
    temp_file.flush()
    shutil.copy2(temp_file.name, filename)


def safe_rename(filename):
    """Renames 'filename' to 'filename.old'
    """
    old_filename = filename + '.old'
    try:
        shutil.move(filename, old_filename)
        print("Renamed existing file from %s to %s" % (filename, old_filename))
    except IOError, exc:
        if exc.errno != errno.ENOENT:
            print(exc.message)
            raise RuntimeError('ERROR: Failed to rename %s to %s' % (filename, old_filename))


def safe_write(filename, contents):
    """Safely backup the target 'filename' then write 'contents'
    """
    safe_rename(filename)
    atomic_write(filename, contents)
