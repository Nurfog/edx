/* eslint-disable-next-line no-shadow-restricted-names, no-unused-vars */
(function(define, undefined) {
    'use strict';

    define([
        'gettext',
        'js/edxnotes/views/tab_panel',
        'js/edxnotes/views/tab_view',
        'edx-ui-toolkit/js/utils/html-utils'
    ], function(gettext, TabPanelView, TabView, HtmlUtils) {
        // eslint-disable-next-line no-var
        var view = 'Recent Activity';
        // eslint-disable-next-line no-var
        var RecentActivityView = TabView.extend({
            PanelConstructor: TabPanelView.extend({
                id: 'recent-panel',
                title: view,
                className: function() {
                    return [
                        TabPanelView.prototype.className,
                        'note-group'
                    ].join(' ');
                },
                renderContent: function() {
                    this.$el.append(HtmlUtils.HTML(this.getNotes(this.collection.toArray())).toString());
                    return this;
                }
            }),

            tabInfo: {
                identifier: 'view-recent-activity',
                name: gettext('Recent Activity'),
                icon: 'fa fa-clock-o',
                view: view
            }
        });

        return RecentActivityView;
    });
// eslint-disable-next-line no-undef
}).call(this, define || RequireJS.define);
