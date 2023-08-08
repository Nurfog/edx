(function(define) {
    define([
        'jquery',
        'underscore',
        'backbone',
        'gettext',
        'js/discovery/models/filter',
        'js/discovery/views/filter_label',
        'edx-ui-toolkit/js/utils/html-utils'
    ], function($, _, Backbone, gettext, Filter, FilterLabel, HtmlUtils) {
        'use strict';

        return Backbone.View.extend({

            el: '#filter-bar',
            templateId: '#filter_bar-tpl',

            events: {
                'click #clear-all-filters': 'clearAll',
                'click li .discovery-button': 'clearFilter'
            },

            initialize: function() {
                this.tpl = HtmlUtils.template($(this.templateId).html());
                this.render();
                this.listenTo(this.collection, 'remove', this.hideIfEmpty);
                this.listenTo(this.collection, 'add', this.addFilter);
                this.listenTo(this.collection, 'reset', this.resetFilters);
            },

            render: function() {
                HtmlUtils.setHtml(
                    this.$el,
                    this.tpl()
                );
                this.$ul = this.$el.find('ul');
                this.$el.addClass('is-animated');
                return this;
            },

            addFilter: function(filter) {
                // eslint-disable-next-line no-var
                var label = new FilterLabel({model: filter});
                this.$ul.append(label.render().el);
                this.show();
            },

            hideIfEmpty: function() {
                if (this.collection.isEmpty()) {
                    this.hide();
                }
            },

            resetFilters: function() {
                this.$ul.empty();
                this.hide();
            },

            clearFilter: function(event) {
                // eslint-disable-next-line no-var
                var $target = $(event.currentTarget);
                // eslint-disable-next-line no-var
                var filter = this.collection.get($target.data('type'));
                this.trigger('clearFilter', filter.id);
            },

            // eslint-disable-next-line no-unused-vars
            clearAll: function(event) {
                this.trigger('clearAll');
            },

            show: function() {
                this.$el.removeClass('is-collapsed');
            },

            hide: function() {
                this.$ul.empty();
                this.$el.addClass('is-collapsed');
            }

        });
    });
// eslint-disable-next-line no-undef
}(define || RequireJS.define));
