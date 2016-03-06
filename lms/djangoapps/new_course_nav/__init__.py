"""
This app was introduced by Dan Friedman <dfriedman@edx.org> and
Christine Lytwynec <clytwynec@edx.org> during edX's 12th hackathon on
2/29/2016 - 3/1-2016.

The goal was to imagine what course navigation might look like if we
could re-design and re-engineer it from scratch.

The UX design attempts to match Marco's work here:
https://github.com/edx/edx-platform/pull/11493

TODOS:
- Features:
    x Use the pattern library
    x Link into sequentials
    x Add nav within sequentials
    - Add hamburger to toggle between course outline and sequential nav
    - Add breadcrumb
    - Add bookmarks
    - Add courseware search
    - Add ~design~
    - Make sure markup is accessible
    - Add realtime text search to nav app to locate sections?
- Refactorings:
    - Choose a better name for the app
    - Refactor the django app into a separate repository
    - Separate styles from the HTML
- Tests:
    - Django view test
    - Elm unit tests
    - bok_choy tests
- Infra:
    - Figure out a build process for the elm app
    - Add elm to devstack and the build pipeline
    - Minify/optimize/dead code elimination on the build
"""
