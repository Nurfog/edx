(function(define) {
    define([
        'jquery',
        'underscore',
        'backbone',
        'gettext'
    // eslint-disable-next-line no-unused-vars
    ], function($, _, Backbone, gettext) {
        'use strict';

        return Backbone.View.extend({

            tagName: 'section',
            templateId: '#search_facets_section-tpl',
            className: '',
            total: 0,
            terms: {},
            other: 0,
            list: [],
            views: {},
            attributes: {'data-parent-element': 'sidebar'},

            initialize: function() {
                this.tpl = _.template($(this.templateId).html());
            },

            render: function(facetName, displayName, facetStats) {
                this.$el.html(this.tpl({name: facetName, displayName: displayName, stats: facetStats}));
                this.$el.attr('data-facet', facetName);
                this.$views = this.$el.find('ul');
                return this;
            },

            remove: function() {
                $.each(this.list, function(key, facet) {
                    facet.remove();
                });
                this.stopListening();
                this.$el.remove();
            }

        });
    });
// eslint-disable-next-line no-undef
}(define || RequireJS.define));
