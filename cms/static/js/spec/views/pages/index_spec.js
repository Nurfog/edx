// eslint-disable-next-line no-undef
define(['jquery',
    'edx-ui-toolkit/js/utils/spec-helpers/ajax-helpers',
    'common/js/spec_helpers/view_helpers', 'js/index',
    'common/js/components/utils/view_utils'],
function($, AjaxHelpers, ViewHelpers, IndexUtils, ViewUtils) {
    describe('Course listing page', function() {
        // eslint-disable-next-line no-var
        var mockIndexPageHTML = readFixtures('mock/mock-index-page.underscore');

        // eslint-disable-next-line no-var
        var fillInFields = function(org, number, run, name) {
            $('.new-course-org').val(org);
            $('.new-course-number').val(number);
            $('.new-course-run').val(run);
            $('.new-course-name').val(name);
        };

        // eslint-disable-next-line no-var
        var fillInLibraryFields = function(org, number, name) {
            $('.new-library-org').val(org).keyup();
            $('.new-library-number').val(number).keyup();
            $('.new-library-name').val(name).keyup();
        };

        beforeEach(function() {
            ViewHelpers.installMockAnalytics();
            appendSetFixtures(mockIndexPageHTML);
            IndexUtils.onReady();
        });

        afterEach(function() {
            ViewHelpers.removeMockAnalytics();
            delete window.source_course_key;
        });

        it('can dismiss notifications', function() {
            // eslint-disable-next-line no-var
            var requests = AjaxHelpers.requests(this);
            /* eslint-disable-next-line no-undef, no-var */
            var reloadSpy = spyOn(ViewUtils, 'reload');
            $('.dismiss-button').click();
            AjaxHelpers.expectJsonRequest(requests, 'DELETE', 'dummy_dismiss_url');
            AjaxHelpers.respondWithNoContent(requests);
            expect(reloadSpy).toHaveBeenCalled();
        });

        it('saves new courses', function() {
            // eslint-disable-next-line no-var
            var requests = AjaxHelpers.requests(this);
            /* eslint-disable-next-line no-undef, no-var */
            var redirectSpy = spyOn(ViewUtils, 'redirect');
            $('.new-course-button').click();
            AjaxHelpers.expectJsonRequest(requests, 'GET', '/organizations');
            AjaxHelpers.respondWithJson(requests, ['DemoX', 'DemoX2', 'DemoX3']);
            fillInFields('DemoX', 'DM101', '2014', 'Demo course');
            $('.new-course-save').click();
            AjaxHelpers.expectJsonRequest(requests, 'POST', '/course/', {
                org: 'DemoX',
                number: 'DM101',
                run: '2014',
                display_name: 'Demo course'
            });
            AjaxHelpers.respondWithJson(requests, {
                url: 'dummy_test_url'
            });
            expect(redirectSpy).toHaveBeenCalledWith('dummy_test_url');
            $('.new-course-org').autocomplete('destroy');
        });

        it('set the correct direction of text in case of rtl', function() {
            $('body').addClass('rtl');
            $('.new-course-button').click();
            $('.new-course-run').val('2014_T2').trigger('input');
            expect($('.new-course-run').hasClass('placeholder-text-direction')).toBe(false);
            $('.new-course-run').val('').trigger('input');
            expect($('.new-course-run').hasClass('placeholder-text-direction')).toBe(true);
        });

        it('displays an error when saving fails', function() {
            // eslint-disable-next-line no-var
            var requests = AjaxHelpers.requests(this);
            $('.new-course-button').click();
            AjaxHelpers.expectJsonRequest(requests, 'GET', '/organizations');
            AjaxHelpers.respondWithJson(requests, ['DemoX', 'DemoX2', 'DemoX3']);
            fillInFields('DemoX', 'DM101', '2014', 'Demo course');
            $('.new-course-save').click();
            AjaxHelpers.respondWithJson(requests, {
                ErrMsg: 'error message'
            });
            expect($('.create-course .wrap-error')).toHaveClass('is-shown');
            expect($('#course_creation_error')).toContainText('error message');
            expect($('.new-course-save')).toHaveClass('is-disabled');
            expect($('.new-course-save')).toHaveAttr('aria-disabled', 'true');
            $('.new-course-org').autocomplete('destroy');
        });

        it('saves new libraries', function() {
            // eslint-disable-next-line no-var
            var requests = AjaxHelpers.requests(this);
            /* eslint-disable-next-line no-undef, no-var */
            var redirectSpy = spyOn(ViewUtils, 'redirect');
            $('.new-library-button').click();
            fillInLibraryFields('DemoX', 'DM101', 'Demo library');
            $('.new-library-save').click();
            AjaxHelpers.expectJsonRequest(requests, 'POST', '/library/', {
                org: 'DemoX',
                number: 'DM101',
                display_name: 'Demo library'
            });
            AjaxHelpers.respondWithJson(requests, {
                url: 'dummy_test_url'
            });
            expect(redirectSpy).toHaveBeenCalledWith('dummy_test_url');
        });

        it('displays an error when a required field is blank', function() {
            // eslint-disable-next-line no-var
            var requests = AjaxHelpers.requests(this);
            $('.new-library-button').click();
            // eslint-disable-next-line no-var
            var values = ['DemoX', 'DM101', 'Demo library'];
            // Try making each of these three values empty one at a time and ensure the form won't submit:
            // eslint-disable-next-line no-var
            for (var i = 0; i < values.length; i++) {
                /* eslint-disable-next-line camelcase, no-var */
                var values_with_blank = values.slice();
                // eslint-disable-next-line camelcase
                values_with_blank[i] = '';
                fillInLibraryFields.apply(this, values_with_blank);
                expect($('.create-library li.field.text input').parent()).toHaveClass('error');
                expect($('.new-library-save')).toHaveClass('is-disabled');
                expect($('.new-library-save')).toHaveAttr('aria-disabled', 'true');
                $('.new-library-save').click();
                AjaxHelpers.expectNoRequests(requests);
            }
        });

        it('can cancel library creation', function() {
            $('.new-library-button').click();
            fillInLibraryFields('DemoX', 'DM101', 'Demo library');
            $('.new-library-cancel').click();
            expect($('.wrapper-create-library')).not.toHaveClass('is-shown');
            $('.wrapper-create-library form input[type=text]').each(function() {
                expect($(this)).toHaveValue('');
            });
        });

        it('displays an error when saving a library fails', function() {
            // eslint-disable-next-line no-var
            var requests = AjaxHelpers.requests(this);
            $('.new-library-button').click();
            fillInLibraryFields('DemoX', 'DM101', 'Demo library');
            $('.new-library-save').click();
            AjaxHelpers.respondWithError(requests, 400, {
                ErrMsg: 'error message'
            });
            expect($('.create-library .wrap-error')).toHaveClass('is-shown');
            expect($('#library_creation_error')).toContainText('error message');
            expect($('.new-library-save')).toHaveClass('is-disabled');
            expect($('.new-library-save')).toHaveAttr('aria-disabled', 'true');
        });

        it('can switch tabs', function() {
            /* eslint-disable-next-line camelcase, no-var */
            var $courses_tab = $('.courses-tab'),
                // eslint-disable-next-line camelcase
                $libraraies_tab = $('.libraries-tab');

            // precondition check - courses tab is loaded by default
            expect($courses_tab).toHaveClass('active');
            expect($libraraies_tab).not.toHaveClass('active');

            $('#course-index-tabs .libraries-tab').click(); // switching to library tab
            expect($courses_tab).not.toHaveClass('active');
            expect($libraraies_tab).toHaveClass('active');

            $('#course-index-tabs .courses-tab').click(); // switching to course tab
            expect($courses_tab).toHaveClass('active');
            expect($libraraies_tab).not.toHaveClass('active');
        });
    });
});
