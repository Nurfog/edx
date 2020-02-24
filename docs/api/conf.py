"""
Configuration for the automatically-generated API docs.
"""
import sys

from path import Path

root = Path("../..").abspath()
sys.path.insert(0, root)

# pylint: disable=wrong-import-position,redefined-builtin,wildcard-import
from docs.baseconf import *

project = u"Open edX REST APIs"
extensions = [
    "sphinxcontrib.openapi",
]

# Prefix document path to section labels, otherwise autogenerated labels would look
# like 'heading' rather than 'path/to/file:heading'
autosectionlabel_prefix_document = True
