/* eslint-disable-next-line no-use-before-define, no-var */
var edx = edx || {};
// eslint-disable-next-line no-var
var onCertificatesReady = null;

(function($, gettext, _) {
    'use strict';

    edx.instructor_dashboard = edx.instructor_dashboard || {};
    edx.instructor_dashboard.certificates = {};

    onCertificatesReady = function() {
        /**
         * Show a confirmation message before letting staff members
         * enable/disable self-generated certificates for a course.
         */
        $('#enable-certificates-form').on('submit', function(event) {
            // eslint-disable-next-line no-var
            var isEnabled = $('#certificates-enabled').val() === 'true',
                confirmMessage = '';

            if (isEnabled) {
                confirmMessage = gettext('Allow students to generate certificates for this course?');
            } else {
                confirmMessage = gettext('Prevent students from generating certificates in this course?');
            }

            /* eslint-disable-next-line no-alert, no-restricted-globals */
            if (!confirm(confirmMessage)) {
                event.preventDefault();
            }
        });

        /**
         * Refresh the status for example certificate generation
         * by reloading the instructor dashboard.
         */
        $('#refresh-example-certificate-status').on('click', function() {
            window.location.reload();
        });

        /**
         * Start generating certificates for all students.
         */
        // eslint-disable-next-line no-var
        var $section = $('section#certificates');
        $section.on('click', '#btn-start-generating-certificates', function(event) {
            /* eslint-disable-next-line no-alert, no-restricted-globals */
            if (!confirm(gettext('Start generating certificates for all students in this course?'))) {
                event.preventDefault();
                return;
            }

            /* eslint-disable-next-line camelcase, no-var */
            var $btn_generating_certs = $(this),
                // eslint-disable-next-line camelcase
                $certificate_generation_status = $('.certificate-generation-status');
            /* eslint-disable-next-line camelcase, no-var */
            var url = $btn_generating_certs.data('endpoint');
            $.ajax({
                type: 'POST',
                url: url,
                success: function(data) {
                    // eslint-disable-next-line camelcase
                    $btn_generating_certs.attr('disabled', 'disabled');
                    // eslint-disable-next-line camelcase
                    $certificate_generation_status.text(data.message);
                },
                // eslint-disable-next-line no-unused-vars
                error: function(jqXHR, textStatus, errorThrown) {
                    // eslint-disable-next-line camelcase
                    $certificate_generation_status.text(gettext('Error while generating certificates. Please try again.'));
                }
            });
        });

        /**
         * Start regenerating certificates for students.
         */
        $section.on('click', '#btn-start-regenerating-certificates', function(event) {
            /* eslint-disable-next-line no-alert, no-restricted-globals */
            if (!confirm(gettext('Start regenerating certificates for students in this course?'))) {
                event.preventDefault();
                return;
            }

            /* eslint-disable-next-line camelcase, no-var */
            var $btn_regenerating_certs = $(this),
                // eslint-disable-next-line camelcase
                $certificate_regeneration_status = $('.certificate-regeneration-status'),
                // eslint-disable-next-line camelcase
                url = $btn_regenerating_certs.data('endpoint');

            $.ajax({
                type: 'POST',
                data: $('#certificate-regenerating-form').serializeArray(),
                url: url,
                success: function(data) {
                    // eslint-disable-next-line camelcase
                    $btn_regenerating_certs.attr('disabled', 'disabled');
                    if (data.success) {
                        // eslint-disable-next-line camelcase
                        $certificate_regeneration_status.text(data.message).addClass('message');
                    } else {
                        // eslint-disable-next-line camelcase
                        $certificate_regeneration_status.text(data.message).addClass('message');
                    }
                },
                error: function(jqXHR) {
                    try {
                        // eslint-disable-next-line no-var
                        var response = JSON.parse(jqXHR.responseText);
                        // eslint-disable-next-line camelcase
                        $certificate_regeneration_status.text(gettext(response.message)).addClass('message');
                    } catch (error) {
                        // eslint-disable-next-line camelcase
                        $certificate_regeneration_status
                            .text(gettext('Error while regenerating certificates. Please try again.'))
                            .addClass('message');
                    }
                }
            });
        });
    };

    // Call onCertificatesReady on document.ready event
    $(onCertificatesReady);

    // eslint-disable-next-line no-var
    var Certificates = (function() {
        // eslint-disable-next-line no-shadow
        function Certificates($section) {
            $section.data('wrapper', this);
            this.instructor_tasks = new window.InstructorDashboard.util.PendingInstructorTasks($section);
        }

        Certificates.prototype.onClickTitle = function() {
            return this.instructor_tasks.task_poller.start();
        };

        Certificates.prototype.onExit = function() {
            return this.instructor_tasks.task_poller.stop();
        };
        return Certificates;
    }());

    _.defaults(window, {
        InstructorDashboard: {}
    });

    _.defaults(window.InstructorDashboard, {
        sections: {}
    });

    _.defaults(window.InstructorDashboard.sections, {
        Certificates: Certificates
    });
// eslint-disable-next-line no-undef
}($, gettext, _));
