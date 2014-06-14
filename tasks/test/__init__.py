"""
Unit test tasks
"""
import os
import sys
from invoke import task, Collection
from invoke import run as sh
from tasks.utils.test import suites
from tasks.utils.envs import Env
from .js import ns as ns_js
from .bok_choy import ns as ns_bok_choy

ns = Collection()
ns.add_collection(ns_js)
ns.add_collection(ns_bok_choy)

try:
    from pygments.console import colorize
except ImportError:
    colorize = lambda color, text: text  # pylint: disable-msg=invalid-name

__test__ = False  # do not collect


@task('prereqs.install', help={
    "system": "System to act on",
    "test_id": "Test id",
    "failed": "Run only failed tests",
    "fail_fast": "Run only failed tests",
    "fasttest": "Run without collectstatic",
    "verbosity": "Turn logging up or down",
})
def test_system(
        system=None, test_id=None, failed=None, fail_fast=None,
        fasttest=None, verbosity=1
    ):
    """
    Run tests on our djangoapps for lms and cms
    """
    opts = {
        'failed_only': failed,
        'fail_fast': fail_fast,
        'fasttest': fasttest,
        'verbosity': verbosity,
    }

    if test_id:
        if not system:
            system = test_id.split('/')[0]
        opts['test_id'] = test_id

    if test_id or system:
        system_tests = [suites.SystemTestSuite(system, **opts)]
    else:
        system_tests = []
        for syst in ('cms', 'lms'):
            system_tests.append(suites.SystemTestSuite(syst, **opts))

    test_suite = suites.PythonTestSuite('python tests', subsuites=system_tests, **opts)
    test_suite.run()

ns.add_task(test_system, 'system')


@task('prereqs.install', help={
    "lib": "lib to test",
    "test_id": "Test id",
    "failed": "Run only failed tests",
    "fail_fast": "Run only failed tests",
    "verbosity": "Turn logging up or down",
})
def test_lib(
        lib=None, test_id=None, failed=None, fail_fast=None,
        verbosity=1,
    ):
    """
    Run tests for common/lib/
    """
    test_id = test_id or lib

    opts = {
        'failed_only': failed,
        'fail_fast': fail_fast,
        'verbosity': verbosity,
    }

    if test_id:
        lib = '/'.join(test_id.split('/')[0:3])
        opts['test_id'] = test_id
        lib_tests = [suites.LibTestSuite(lib, **opts)]
    else:
        lib_tests = [suites.LibTestSuite(d, **opts) for d in Env.LIB_TEST_DIRS]

    test_suite = suites.PythonTestSuite('python tests', subsuites=lib_tests, **opts)
    test_suite.run()

ns.add_task(test_lib, 'lib')

@task('prereqs.install', help={
    "failed": "Run only failed tests",
    "fail_fast": "Run only failed tests",
    "verbosity": "Turn logging up or down",
})
def test_python(failed=None, fail_fast=None, verbosity=1):
    """
    Run all python tests
    """
    opts = {
        'failed_only': failed,
        'fail_fast': fail_fast,
        'verbosity': verbosity,
    }

    python_suite = suites.PythonTestSuite('Python Tests', **opts)
    python_suite.run()

ns.add_task(test_python, 'python')

@task('prereqs.install.python')
def test_i18n():
    """
    Run all i18n tests
    """
    i18n_suite = suites.I18nTestSuite('i18n')
    i18n_suite.run()

ns.add_task(test_i18n, 'i18n')


@task('prereqs.install', help={
    "verbosity": "Turn logging up or down"
})
def test_all(verbosity=1):
    """
    Run all tests
    """
    opts = {
        'verbosity': verbosity,
    }
    # Subsuites to be added to the main suite
    python_suite = suites.PythonTestSuite('Python Tests', **opts)
    i18n_suite = suites.I18nTestSuite('i18n', **opts)
    js_suite = suites.JsTestSuite('JS Tests', mode='run', with_coverage=True)

    # Main suite to be run
    all_unittests_suite = suites.TestSuite('All Tests', subsuites=[i18n_suite, js_suite, python_suite])
    all_unittests_suite.run()

ns.add_task(test_all, 'all', default=True)

@task('prereqs.install', help={
    "compare_branch": "Branch to compare against"
})
def coverage(compare_branch="origin/master"):
    """
    Build the html, xml, and diff coverage reports
    """
    for directory in Env.LIB_TEST_DIRS + ['cms', 'lms']:
        report_dir = Env.REPORT_DIR / directory

        if (report_dir / '.coverage').isfile():
            # Generate the coverage.py HTML report
            sh("coverage html --rcfile={dir}/.coveragerc".format(dir=directory))

            # Generate the coverage.py XML report
            sh("coverage xml -o {report_dir}/coverage.xml --rcfile={dir}/.coveragerc".format(
                report_dir=report_dir,
                dir=directory
            ))

    # Find all coverage XML files (both Python and JavaScript)
    xml_reports = []

    for filepath in Env.REPORT_DIR.walk():
        if filepath.basename() == 'coverage.xml':
            xml_reports.append(filepath)

    if not xml_reports:
        err_msg = colorize(
            'red',
            "No coverage info found.  Run `inv test` before running `inv test.coverage`.\n"
        )
        sys.stderr.write(err_msg)
    else:
        xml_report_str = ' '.join(xml_reports)
        diff_html_path = os.path.join(Env.REPORT_DIR, 'diff_coverage_combined.html')

        # Generate the diff coverage reports (HTML and console)

        sh("diff-cover {xml_report_str}".format(xml_report_str=xml_report_str))

        sh(
            "diff-cover {xml_report_str} --compare-branch={compare_branch} "
            "--html-report {diff_html_path}".format(
                xml_report_str=xml_report_str,
                compare_branch=compare_branch,
                diff_html_path=diff_html_path,
            )
        )

        sh(
            "diff-cover {xml_report_str} --compare-branch="
            "{compare_branch}".format(
                xml_report_str=xml_report_str,
                compare_branch=compare_branch,
            )
        )

        print("\n")

ns.add_task(coverage, 'coverage')
