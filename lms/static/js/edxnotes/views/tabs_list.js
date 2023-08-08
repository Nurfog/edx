/* eslint-disable-next-line no-shadow-restricted-names, no-unused-vars */
(function(define, undefined) {
    'use strict';

    define([
        'underscore', 'backbone', 'js/edxnotes/views/tab_item'
    ], function(_, Backbone, TabItemView) {
        // eslint-disable-next-line no-var
        var TabsListView = Backbone.View.extend({
            tagName: 'ul',
            className: 'tabs',

            initialize: function(options) {
                this.options = options;
                this.listenTo(this.collection, {
                    add: this.createTab,
                    destroy: function(model, collection) {
                        if (model.isActive() && collection.length) {
                            collection.at(0).activate();
                        }
                    }
                });
            },

            render: function() {
                this.collection.each(this.createTab, this);
                if (this.collection.length) {
                    this.collection.at(0).activate();
                }
                return this;
            },

            createTab: function(model) {
                // eslint-disable-next-line no-var
                var tab = new TabItemView({
                    model: model
                });
                tab.render().$el.appendTo(this.$el);
                return tab;
            }
        });

        return TabsListView;
    });
// eslint-disable-next-line no-undef
}).call(this, define || RequireJS.define);
