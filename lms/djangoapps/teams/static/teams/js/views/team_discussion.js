/**
 * View that shows the discussion for a team.
 */
(function(define) {
    'use strict';

    define(['backbone', 'underscore', 'gettext', 'common/js/discussion/views/discussion_inline_view'],
        function(Backbone, _, gettext, DiscussionInlineView) {
            // eslint-disable-next-line no-var
            var TeamDiscussionView = Backbone.View.extend({
                initialize: function(options) {
                    window.$$course_id = this.$el.data('course-id');
                    this.readOnly = options.readOnly;
                },

                render: function() {
                    // eslint-disable-next-line no-var
                    var discussionInlineView = new DiscussionInlineView({
                        el: this.$el,
                        readOnly: this.readOnly,
                        startHeader: 3
                    });
                    discussionInlineView.render();
                    return this;
                }
            });

            return TeamDiscussionView;
        });
// eslint-disable-next-line no-undef
}).call(this, define || RequireJS.define);
