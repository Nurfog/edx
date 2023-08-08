// eslint-disable-next-line no-undef
define(
    ['underscore', 'js/models/active_video_upload', 'js/views/baseview', 'common/js/components/views/feedback_prompt',
        'edx-ui-toolkit/js/utils/html-utils'],
    function(_, ActiveVideoUpload, BaseView, PromptView, HtmlUtils) {
        'use strict';

        // eslint-disable-next-line no-var
        var STATUS_CLASSES = [
            {status: ActiveVideoUpload.STATUS_QUEUED, cls: 'queued'},
            {status: ActiveVideoUpload.STATUS_COMPLETED, cls: 'success'},
            {status: ActiveVideoUpload.STATUS_FAILED, cls: 'error'}
        ];

        // eslint-disable-next-line no-var
        var ActiveVideoUploadView = BaseView.extend({
            tagName: 'li',
            className: 'active-video-upload',

            events: {
                'click a.more-details-action': 'showUploadFailureMessage'
            },

            initialize: function() {
                this.template = this.loadTemplate('active-video-upload');
                this.listenTo(this.model, 'change', this.render);
            },

            render: function() {
                // eslint-disable-next-line no-var
                var $el = this.$el,
                    status;
                $el.html(HtmlUtils.HTML(this.template(this.model.attributes)).toString());
                status = this.model.get('status');
                _.each(
                    STATUS_CLASSES,
                    function(statusClass) {
                        // eslint-disable-next-line eqeqeq
                        $el.toggleClass(statusClass.cls, status == statusClass.status);
                    }
                );
                return this;
            },

            showUploadFailureMessage: function() {
                return new PromptView.Warning({
                    title: gettext('Your file could not be uploaded'),
                    message: this.model.get('failureMessage'),
                    actions: {
                        primary: {
                            text: gettext('Close'),
                            click: function(prompt) {
                                return prompt.hide();
                            }
                        }
                    }
                }).show();
            }
        });

        return ActiveVideoUploadView;
    }
);
