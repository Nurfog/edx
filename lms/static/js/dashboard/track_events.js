/**
 * Track interaction with the student dashboard..
 */

/* eslint-disable-next-line no-use-before-define, no-var */
var edx = edx || {};

(function($) {
    'use strict';

    edx.dashboard = edx.dashboard || {};

    // Generate the properties object to be passed along with business intelligence events.
    edx.dashboard.generateTrackProperties = function(element) {
        // eslint-disable-next-line no-var
        var $el = $(element),
            properties = {};

        properties.category = 'dashboard';
        properties.label = $el.data('course-key');

        return properties;
    };

    // Emit an event when the 'course title link' is clicked.
    edx.dashboard.trackCourseTitleClicked = function($courseTitleLink, properties) {
        // eslint-disable-next-line no-var
        var trackProperty = properties || edx.dashboard.generateTrackProperties;

        window.analytics.trackLink(
            $courseTitleLink,
            'edx.bi.dashboard.course_title.clicked',
            trackProperty
        );
    };

    // Emit an event  when the 'course image' is clicked.
    edx.dashboard.trackCourseImageLinkClicked = function($courseImageLink, properties) {
        // eslint-disable-next-line no-var
        var trackProperty = properties || edx.dashboard.generateTrackProperties;
        window.analytics.trackLink(
            $courseImageLink,
            'edx.bi.dashboard.course_image.clicked',
            trackProperty
        );
    };

    // Emit an event  when the 'View Course' button is clicked.
    edx.dashboard.trackEnterCourseLinkClicked = function($enterCourseLink, properties) {
        // eslint-disable-next-line no-var
        var trackProperty = properties || edx.dashboard.generateTrackProperties;
        window.analytics.trackLink(
            $enterCourseLink,
            'edx.bi.dashboard.enter_course.clicked',
            trackProperty
        );
    };

    // Emit an event when the options dropdown is engaged.
    edx.dashboard.trackCourseOptionDropdownClicked = function($optionsDropdown, properties) {
        // eslint-disable-next-line no-var
        var trackProperty = properties || edx.dashboard.generateTrackProperties;
        window.analytics.trackLink(
            $optionsDropdown,
            'edx.bi.dashboard.course_options_dropdown.clicked',
            trackProperty
        );
    };

    // Emit an event  when the 'Learn about verified' link is clicked.
    edx.dashboard.trackLearnVerifiedLinkClicked = function($courseLearnVerified, properties) {
        // eslint-disable-next-line no-var
        var trackProperty = properties || edx.dashboard.generateTrackProperties;
        window.analytics.trackLink(
            $courseLearnVerified,
            'edx.bi.dashboard.verified_info_link.clicked',
            trackProperty
        );
    };

    // Emit an event  when the 'Find Courses' button is clicked.
    edx.dashboard.trackFindCourseBtnClicked = function($findCoursesBtn, properties) {
        // eslint-disable-next-line no-var
        var trackProperty = properties || {category: 'dashboard', label: 'sidebar'};
        window.analytics.trackLink(
            $findCoursesBtn,
            'edx.bi.dashboard.find_courses_button.clicked',
            trackProperty
        );
    };

    $(document).ready(function() {
        if (!window.analytics) {
            return;
        }
        edx.dashboard.trackCourseTitleClicked($('.course-title > a'));
        edx.dashboard.trackCourseImageLinkClicked($('.cover'));
        edx.dashboard.trackEnterCourseLinkClicked($('.enter-course'));
        edx.dashboard.trackCourseOptionDropdownClicked($('.wrapper-action-more'));
        edx.dashboard.trackLearnVerifiedLinkClicked($('.verified-info'));
        edx.dashboard.trackFindCourseBtnClicked($('.btn-find-courses'));
        edx.dashboard.trackFindCourseBtnClicked(
            $('.discover-new-link'),
            {category: 'dashboard', label: 'header'}
        );
    });
// eslint-disable-next-line no-undef
}(jQuery));
