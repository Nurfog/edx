// eslint-disable-next-line no-undef
define(['domReady', 'jquery', 'underscore', 'js/utils/cancel_on_escape', 'js/views/utils/create_course_utils',
    'js/views/utils/create_library_utils', 'common/js/components/utils/view_utils'],
function(domReady, $, _, CancelOnEscape, CreateCourseUtilsFactory, CreateLibraryUtilsFactory, ViewUtils) {
    'use strict';

    // eslint-disable-next-line no-var
    var CreateCourseUtils = new CreateCourseUtilsFactory({
        name: '.new-course-name',
        org: '.new-course-org',
        number: '.new-course-number',
        run: '.new-course-run',
        save: '.new-course-save',
        errorWrapper: '.create-course .wrap-error',
        errorMessage: '#course_creation_error',
        tipError: '.create-course span.tip-error',
        error: '.create-course .error',
        allowUnicode: '.allow-unicode-course-id'
    }, {
        shown: 'is-shown',
        showing: 'is-showing',
        hiding: 'is-hiding',
        disabled: 'is-disabled',
        error: 'error'
    });

    // eslint-disable-next-line no-var
    var CreateLibraryUtils = new CreateLibraryUtilsFactory({
        name: '.new-library-name',
        org: '.new-library-org',
        number: '.new-library-number',
        save: '.new-library-save',
        errorWrapper: '.create-library .wrap-error',
        errorMessage: '#library_creation_error',
        tipError: '.create-library  span.tip-error',
        error: '.create-library .error',
        allowUnicode: '.allow-unicode-library-id'
    }, {
        shown: 'is-shown',
        showing: 'is-showing',
        hiding: 'is-hiding',
        disabled: 'is-disabled',
        error: 'error'
    });

    // eslint-disable-next-line no-var
    var saveNewCourse = function(e) {
        e.preventDefault();

        if (CreateCourseUtils.hasInvalidRequiredFields()) {
            return;
        }

        // eslint-disable-next-line no-var
        var $newCourseForm = $(this).closest('#create-course-form');
        /* eslint-disable-next-line camelcase, no-var */
        var display_name = $newCourseForm.find('.new-course-name').val();
        // eslint-disable-next-line no-var
        var org = $newCourseForm.find('.new-course-org').val();
        // eslint-disable-next-line no-var
        var number = $newCourseForm.find('.new-course-number').val();
        // eslint-disable-next-line no-var
        var run = $newCourseForm.find('.new-course-run').val();

        /* eslint-disable-next-line camelcase, no-var */
        var course_info = {
            org: org,
            number: number,
            // eslint-disable-next-line camelcase
            display_name: display_name,
            run: run
        };

        // eslint-disable-next-line no-undef
        analytics.track('Created a Course', course_info);
        CreateCourseUtils.create(course_info, function(errorMessage) {
            // eslint-disable-next-line no-var
            var msg = edx.HtmlUtils.joinHtml(edx.HtmlUtils.HTML('<p>'), errorMessage, edx.HtmlUtils.HTML('</p>'));
            $('.create-course .wrap-error').addClass('is-shown');
            edx.HtmlUtils.setHtml($('#course_creation_error'), msg);
            $('.new-course-save').addClass('is-disabled').attr('aria-disabled', true);
        });
    };

    // eslint-disable-next-line no-var
    var rtlTextDirection = function() {
        // eslint-disable-next-line no-var
        var Selectors = {
            new_course_run: '#new-course-run'
        };

        if ($('body').hasClass('rtl')) {
            $(Selectors.new_course_run).addClass('course-run-text-direction placeholder-text-direction');
            $(Selectors.new_course_run).on('input', function() {
                if (this.value === '') {
                    $(Selectors.new_course_run).addClass('placeholder-text-direction');
                } else {
                    $(Selectors.new_course_run).removeClass('placeholder-text-direction');
                }
            });
        }
    };

    // eslint-disable-next-line no-var
    var makeCancelHandler = function(addType) {
        return function(e) {
            e.preventDefault();
            $('.new-' + addType + '-button').removeClass('is-disabled').attr('aria-disabled', false);
            $('.wrapper-create-' + addType).removeClass('is-shown');
            // Clear out existing fields and errors
            $('#create-' + addType + '-form input[type=text]').val('');
            $('#' + addType + '_creation_error').html('');
            $('.create-' + addType + ' .wrap-error').removeClass('is-shown');
            $('.new-' + addType + '-save').off('click');
        };
    };

    // eslint-disable-next-line no-var
    var addNewCourse = function(e) {
        // eslint-disable-next-line no-var
        var $newCourse,
            $cancelButton,
            $courseName;
        e.preventDefault();
        $('.new-course-button').addClass('is-disabled').attr('aria-disabled', true);
        $('.new-course-save').addClass('is-disabled').attr('aria-disabled', true);
        $newCourse = $('.wrapper-create-course').addClass('is-shown');
        $cancelButton = $newCourse.find('.new-course-cancel');
        $courseName = $('.new-course-name');
        $courseName.focus().select();
        $('.new-course-save').on('click', saveNewCourse);
        $cancelButton.bind('click', makeCancelHandler('course'));
        CancelOnEscape($cancelButton);
        CreateCourseUtils.setupOrgAutocomplete();
        CreateCourseUtils.configureHandlers();
        rtlTextDirection();
    };

    // eslint-disable-next-line no-var
    var saveNewLibrary = function(e) {
        e.preventDefault();

        if (CreateLibraryUtils.hasInvalidRequiredFields()) {
            return;
        }

        // eslint-disable-next-line no-var
        var $newLibraryForm = $(this).closest('#create-library-form');
        /* eslint-disable-next-line camelcase, no-var */
        var display_name = $newLibraryForm.find('.new-library-name').val();
        // eslint-disable-next-line no-var
        var org = $newLibraryForm.find('.new-library-org').val();
        // eslint-disable-next-line no-var
        var number = $newLibraryForm.find('.new-library-number').val();

        /* eslint-disable-next-line camelcase, no-var */
        var lib_info = {
            org: org,
            number: number,
            // eslint-disable-next-line camelcase
            display_name: display_name
        };

        // eslint-disable-next-line no-undef
        analytics.track('Created a Library', lib_info);
        CreateLibraryUtils.create(lib_info, function(errorMessage) {
            // eslint-disable-next-line no-var
            var msg = edx.HtmlUtils.joinHtml(edx.HtmlUtils.HTML('<p>'), errorMessage, edx.HtmlUtils.HTML('</p>'));
            $('.create-library .wrap-error').addClass('is-shown');
            edx.HtmlUtils.setHtml($('#library_creation_error'), msg);
            $('.new-library-save').addClass('is-disabled').attr('aria-disabled', true);
        });
    };

    // eslint-disable-next-line no-var
    var addNewLibrary = function(e) {
        e.preventDefault();
        $('.new-library-button').addClass('is-disabled').attr('aria-disabled', true);
        $('.new-library-save').addClass('is-disabled').attr('aria-disabled', true);
        // eslint-disable-next-line no-var
        var $newLibrary = $('.wrapper-create-library').addClass('is-shown');
        // eslint-disable-next-line no-var
        var $cancelButton = $newLibrary.find('.new-library-cancel');
        // eslint-disable-next-line no-var
        var $libraryName = $('.new-library-name');
        $libraryName.focus().select();
        $('.new-library-save').on('click', saveNewLibrary);
        $cancelButton.bind('click', makeCancelHandler('library'));
        CancelOnEscape($cancelButton);

        CreateLibraryUtils.configureHandlers();
    };

    // eslint-disable-next-line no-var
    var showTab = function(tab) {
        return function(e) {
            e.preventDefault();
            window.location.hash = tab;
            $('.courses-tab').toggleClass('active', tab === 'courses-tab');
            $('.archived-courses-tab').toggleClass('active', tab === 'archived-courses-tab');
            $('.libraries-tab').toggleClass('active', tab === 'libraries-tab');

            // Also toggle this course-related notice shown below the course tab, if it is present:
            $('.wrapper-creationrights').toggleClass('is-hidden', tab !== 'courses-tab');
        };
    };

    // eslint-disable-next-line no-var
    var onReady = function() {
        // eslint-disable-next-line no-var
        var courseTabHref = $('#course-index-tabs .courses-tab a').attr('href');
        // eslint-disable-next-line no-var
        var libraryTabHref = $('#course-index-tabs .libraries-tab a').attr('href');
        // eslint-disable-next-line no-var
        var ArchivedTabHref = $('#course-index-tabs .archived-courses-tab a').attr('href');

        $('.new-course-button').bind('click', addNewCourse);
        $('.new-library-button').bind('click', addNewLibrary);

        $('.dismiss-button').bind('click', ViewUtils.deleteNotificationHandler(function() {
            ViewUtils.reload();
        }));

        $('.action-reload').bind('click', ViewUtils.reload);

        if (courseTabHref === '#') {
            $('#course-index-tabs .courses-tab').bind('click', showTab('courses-tab'));
        }

        if (libraryTabHref === '#') {
            $('#course-index-tabs .libraries-tab').bind('click', showTab('libraries-tab'));
        }

        if (ArchivedTabHref === '#') {
            $('#course-index-tabs .archived-courses-tab').bind('click', showTab('archived-courses-tab'));
        }
        if (window.location.hash) {
            $(window.location.hash.replace('#', '.')).first('a').trigger('click');
        }
    };

    domReady(onReady);

    return {
        onReady: onReady
    };
});
