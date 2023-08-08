// eslint-disable-next-line no-unused-vars
/* globals DiscussionContentShowView, DiscussionUtil, MathJax */
(function() {
    'use strict';

    // eslint-disable-next-line no-var
    var __hasProp = {}.hasOwnProperty,
        __extends = function(child, parent) {
            /* eslint-disable-next-line no-var, no-restricted-syntax */
            for (var key in parent) {
                if (__hasProp.call(parent, key)) {
                    child[key] = parent[key];
                }
            }
            function ctor() {
                this.constructor = child;
            }

            ctor.prototype = parent.prototype;
            child.prototype = new ctor();
            child.__super__ = parent.prototype;
            return child;
        };

    // eslint-disable-next-line no-undef
    if (typeof Backbone !== 'undefined' && Backbone !== null) {
        this.ResponseCommentShowView = (function(_super) {
            // eslint-disable-next-line no-use-before-define
            __extends(ResponseCommentShowView, _super);

            function ResponseCommentShowView() {
                // eslint-disable-next-line no-var
                var self = this;
                this.edit = function() {
                    return ResponseCommentShowView.prototype.edit.apply(self, arguments);
                };
                this._delete = function() {
                    return ResponseCommentShowView.prototype._delete.apply(self, arguments);
                };
                return ResponseCommentShowView.__super__.constructor.apply(this, arguments);
            }

            ResponseCommentShowView.prototype.tagName = 'li';

            ResponseCommentShowView.prototype.render = function() {
                // eslint-disable-next-line no-var
                var template = edx.HtmlUtils.template($('#response-comment-show-template').html());
                /* eslint-disable-next-line no-undef, no-var */
                var context = _.extend({
                    cid: this.model.cid,
                    author_display: this.getAuthorDisplay(),
                    readOnly: $('.discussion-module').data('read-only')
                }, this.model.attributes);

                edx.HtmlUtils.setHtml(this.$el, template(context));
                this.delegateEvents();
                this.renderAttrs();
                this.$el.find('.timeago').timeago();
                this.convertMath();
                this.addReplyLink();
                return this;
            };

            // eslint-disable-next-line consistent-return
            ResponseCommentShowView.prototype.addReplyLink = function() {
                // eslint-disable-next-line no-var
                var html, name;
                // eslint-disable-next-line no-prototype-builtins
                if (this.model.hasOwnProperty('parent')) {
                    name = this.model.parent.get('username') || gettext('anonymous');
                    html = edx.HtmlUtils.interpolateHtml(
                        edx.HtmlUtils.HTML("<a href='#comment_{parent_id}'>@{name}</a>:  "),
                        {
                            parent_id: this.model.parent.id,
                            name: name
                        }
                    );
                    return edx.HtmlUtils.prepend(
                        this.$('.response-body p:first'),
                        html
                    );
                }
            };

            ResponseCommentShowView.prototype.convertMath = function() {
                DiscussionUtil.convertMath(this.$el.find('.response-body'));
                DiscussionUtil.typesetMathJax(this.$el.find('.response-body'));
            };

            ResponseCommentShowView.prototype._delete = function(event) {
                return this.trigger('comment:_delete', event);
            };

            ResponseCommentShowView.prototype.edit = function(event) {
                return this.trigger('comment:edit', event);
            };

            return ResponseCommentShowView;
        }(DiscussionContentShowView));
    }
}).call(window);
