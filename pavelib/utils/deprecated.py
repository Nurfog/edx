from __future__ import print_function
from invoke import run as sh
from pygments.console import colorize

def deprecated(deprecated_by):
    def deprecated_decorator(func):
        def wrapper(*args, **kwargs):
            sh("pip install -q -r requirements/edx/invoke.txt")
            print(colorize("darkred", "Task {name} has been deprecated. Use '{deprecated_by}' instead.".\
                  format(name=func.__name__, deprecated_by=deprecated_by)))
            sh(deprecated_by, echo=True)
        # Copy over the necessary metadata
        wrapper.__name__ = func.__name__
        wrapper.__module__ = func.__module__
        wrapper.__doc__ = func.__doc__
        return wrapper
    return deprecated_decorator
