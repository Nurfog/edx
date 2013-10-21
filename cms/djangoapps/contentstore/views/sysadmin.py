"""
sysadmin - a custom page for MITx that they use to manage their instance. This page is enabled via
a FEATURE FLAG
"""
import subprocess
import logging

from django_future.csrf import ensure_csrf_cookie
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect
from django.conf import settings
from django.http import HttpResponse
from django.utils.translation import ugettext as _
from django.http import Http404

from xmodule.modulestore.django import modulestore

from mitxmako.shortcuts import render_to_response

#import pymongo
import time
import json


@login_required
@ensure_csrf_cookie
def sysadmin(request):
    """
    sysadmin page: for now, just list courses and allow deletion
    """
    if (not request.user) or (not request.user.is_staff):
        return redirect('login')

    if not settings.MITX_FEATURES.get('ENABLE_MITX_SYSADMIN_PAGE', False):
        raise Http404

    collection = modulestore().collection

    msg = ''
    bdir = getattr(settings, 'DELETED_COURSE_BACKUPS_DIR', None)
    
    action = request.GET.get('action', request.POST.get('action', ''))
    course_id = request.GET.get('course_id', '')

    if action=='delete':
        if not course_id:
            msg += "<font color='red'>{0}</font>".format(_('Error - no course specified'))
        else:
            nrec = collection.find({'_id.course': course_id}).count()
            if not 'really' in request.GET:
                msg += _("Really delete course {0}?\n").format(course_id)
                msg += _("{0} records for this course in the database").format(nrec)
                logging.debug('Delete course %s requested' % course_id)
            else:
                msg += _("deleting {0}: ").format(course_id)
                data = collection.find({'_id.course': course_id})
                fn = 'course-%s-dump-%s.json' % (course_id, time.ctime(time.time()).replace(' ','_'))
                if bdir is not None:
                    with open('%s/%s' % (bdir, fn), 'w') as fp:
                        for d in data:
                            fp.write(json.dumps(d)+'\n')
                collection.remove({'_id.course': course_id})
                msg += _("{0} records for {1} removed (backup file {2})").format(nrec, course_id, fn)
                logging.debug('Course %s deleted!' % course_id)
                action = ""

    elif action=='dump':
        if not course_id:
            msg += "<font color='red'>{0}</font>".format(_("Error - no course specified"))
        else:
            data = collection.find({'_id.course': course_id})
            response = HttpResponse(mimetype='text/json')
            fn = 'course-%s-dump-%s.json' % (course_id, time.ctime(time.time()).replace(' ','_'))
            response['Content-Disposition'] = 'attachment; filename={0}'.format(fn)
            data = collection.find({'_id.course': course_id})
            for d in data:
                response.write(json.dumps(d)+'\n')
            return response
        
    elif action=='Add Course' and request.method=='POST':
        '''
        Add course by running external script, given git URL provided in input form
        '''
        giturl = request.POST.get('giturl', '')
        acscript = getattr(settings, 'CMS_ADD_COURSE_SCRIPT', '')
        cmd = '{0} "{1}"'.format(acscript, giturl)
        logging.debug('Adding course with command: {0}'.format(cmd))
        ret = subprocess.Popen(cmd, shell=True, executable = "/bin/bash",
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
        ret = ''.join(ret)
        msg = "<font color='red'>{0} {1}</font>".format(_("Added course from"), giturl)
        msg += "<pre>{0}</pre>".format(ret.replace('<','&lt;'))

    #-----------------------------------------------------------------------------
    # get list of courses
    
    ctab = {}
    idtab = {}
    courses = collection.distinct('_id.course')
    for course in courses:
        cinfo = collection.find_one({'_id.course':course, '_id.category':'course'}) or {}
        id = cinfo.get('_id',cinfo)
        name = id.get('name',id)
        ctab[course] = name
        idtab[course] = id

    context = {'ctab': ctab,
               'idtab': idtab,
               'msg': msg, 
               'course_id': course_id, 
               'action': action,
               }
    return render_to_response('sysadmin.html', context)
