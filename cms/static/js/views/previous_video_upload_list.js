define([
    'jquery', 'underscore', 'backbone', 
    'gettext',
    'js/views/baseview',
    'js/views/paging',
    'js/views/previous_video_upload',
    'common/js/components/views/paging_footer',
    'js/views/paging_header',
    'js/views/search'],

    function($, _, Backbone, gettext, BaseView, PagingView,
        PreviousVideoUploadView, PagingFooter, PagingHeader, SearchView) {
        'use strict';
        var PreviousVideoUploadListView = BaseView.extend({
            tagName: 'section',
            className: 'wrapper-assets',

            events: {
                'click .column-sort-link': 'onToggleColumn'
            },

            initialize: function(options) {
                this.pagingView = new this.PreviousVideoUploadPagingView({
                    el: this.$el,
                    collection: this.collection,
                    encodingsDownloadUrl: options.encodingsDownloadUrl,
                    videoHandlerUrl: options.videoHandlerUrl,
                    template: this.loadTemplate('previous-video-upload-list')
                });
                this.pagingView.registerSortableColumn('js-video-date-col', gettext('Date Added'), 'created', 'desc');
                this.pagingView.registerSortableColumn('js-video-name-col', gettext('Name'), 'client_video_id', 'asc');
                this.pagingView.registerSortableColumn('js-video-duration-col', gettext('Duration'), 'duration', 'asc');
                this.pagingView.setInitialSortColumn('js-video-date-col')
            },

            PreviousVideoUploadPagingView: PagingView.extend({
                initialize: function(options) {
                    PagingView.prototype.initialize.call(this);
                    this.encodingsDownloadUrl = options.encodingsDownloadUrl;
                    this.videoHandlerUrl = options.videoHandlerUrl;
                    this.template = options.template;
                },

                renderPageItems: function() {
                    var videoHandlerUrl = this.videoHandlerUrl;
                    this.itemViews = this.collection.map(function(model) {
                        return new PreviousVideoUploadView({
                            model: model,
                            videoHandlerUrl: videoHandlerUrl,
                        });
                    });

                    var $el = this.$el,
                    $tabBody;
                    $el.html(this.template({encodingsDownloadUrl: this.encodingsDownloadUrl}));
                    $tabBody = $el.find('.js-table-body');
                    _.each(this.itemViews, function(view) {
                        $tabBody.append(view.render().$el);
                    });
                    this.pagingHeader = new PagingHeader({view: this, el: $el.find('#video-paging-header')});
                    this.pagingFooter = new PagingFooter({collection: this.collection, el: $el.find('#video-paging-footer')});
                    this.searchView = new SearchView({el: this.$el.find('.forum-search'), collection: this.collection});

                    this.pagingHeader.render();
                    this.pagingFooter.render();
                    this.searchView.render();
                }

            }),

            onToggleColumn: function(event) {
                var columnName = event.target.id;
                this.pagingView.toggleSortOrder(columnName);
            },

            render: function() {
                this.pagingView.renderPageItems();
                return this;
            }
        });

        return PreviousVideoUploadListView;
    }
);
