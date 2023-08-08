// eslint-disable-next-line no-undef
define([
    'jquery', 'js/views/settings/grading', 'js/models/settings/course_grading_policy'
], function($, GradingView, CourseGradingPolicyModel) {
    'use strict';

    return function(courseDetails, gradingUrl, courseAssignmentLists) {
        // eslint-disable-next-line no-var
        var model, editor;

        $('form :input')
            .focus(function() {
                $('label[for="' + this.id + '"]').addClass('is-focused');
            })
            .blur(function() {
                $('label').removeClass('is-focused');
            });

        model = new CourseGradingPolicyModel(courseDetails, {parse: true});
        model.urlRoot = gradingUrl;
        editor = new GradingView({
            el: $('.settings-grading'),
            model: model,
            courseAssignmentLists: courseAssignmentLists
        });
        editor.render();
    };
});
