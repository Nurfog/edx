import logging
from optparse import make_option

from django.core.management.base import BaseCommand
from opaque_keys.edx.keys import CourseKey
from xmodule.modulestore.django import modulestore

from openedx.core.djangoapps.content.course_structures.tasks import update_course_structure


log = logging.getLogger(__name__)


class Command(BaseCommand):
    args = '<course_id course_id ...>'
    help = 'Generates and stores course structure for one or more courses.'

    option_list = BaseCommand.option_list + (
        make_option('--all',
                    action='store_true',
                    default=False,
                    help='Generate structures for all courses.'),
    )

    def handle(self, *args, **options):

        if options['all']:
            course_keys = [course.id for course in modulestore().get_courses()]
        else:
            course_keys = [CourseKey.from_string(arg) for arg in args]

        if not course_keys:
            log.fatal('No courses specified.')
            return

        log.info('Generating course structures for %d courses.', len(course_keys))
        logging.debug('Generating course structure(s) for the following courses: %s', course_keys)

        for course_key in course_keys:
            try:
                update_course_structure(unicode(course_key))
            except Exception as ex:
                log.exception('An error occurred while generating course structure for %s: %s',
                              unicode(course_key), ex.message)

        log.info('Finished generating course structures.')
