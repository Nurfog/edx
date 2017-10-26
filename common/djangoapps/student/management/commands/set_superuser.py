"""Management command to grant or revoke superuser access for one or more users"""

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    """Management command to grant or revoke superuser access for one or more users"""
    args = '<user|email> [user|email ...]>'
    help = """
    This command will set is_superuser to true for one or more users.
    Lookup by username or email address, assumes usernames
    do not look like email addresses.
    """

    def add_arguments(self, parser):
        parser.add_argument('--unset',
                            action='store_true',
                            dest='unset',
                            help='Set is_superuser to False instead of True')

    def handle(self, *args, **options):
        if len(args) < 1:
            raise CommandError('Usage is set_superuser {0}'.format(self.args))

        for user in args:
            try:
                if '@' in user:
                    userobj = User.objects.get(email=user)
                else:
                    userobj = User.objects.get(username=user)

                if options['unset']:
                    userobj.is_superuser = False
                else:
                    userobj.is_superuser = True

                userobj.save()

            except Exception as err:  # pylint: disable=broad-except
                print "Error modifying user with identifier {}: {}: {}".format(user, type(err).__name__, err.message)

        print 'Success!'
