(function(define) {
    'use strict';

    define([
        'underscore', 'backbone', 'course_search/js/search_router', 'course_search/js/views/search_form',
        'course_search/js/collections/search_collection', 'course_search/js/views/dashboard_search_results_view'
    ],
    function(_, Backbone, SearchRouter, SearchForm, SearchCollection, DashboardSearchResultsView) {
        return function() {
            // eslint-disable-next-line no-var
            var router = new SearchRouter();
            // eslint-disable-next-line no-var
            var form = new SearchForm({
                el: $('#dashboard-search-bar')
            });
            // eslint-disable-next-line no-var
            var collection = new SearchCollection([]);
            // eslint-disable-next-line no-var
            var results = new DashboardSearchResultsView({collection: collection});
            // eslint-disable-next-line no-var
            var dispatcher = _.clone(Backbone.Events);

            dispatcher.listenTo(router, 'search', function(query) {
                form.doSearch(query);
            });

            dispatcher.listenTo(form, 'search', function(query) {
                results.showLoadingMessage();
                collection.performSearch(query);
                router.navigate('search/' + query, {replace: true});
            });

            dispatcher.listenTo(form, 'clear', function() {
                collection.cancelSearch();
                results.clear();
                router.navigate('');
            });

            dispatcher.listenTo(results, 'next', function() {
                collection.loadNextPage();
            });

            dispatcher.listenTo(results, 'reset', function() {
                form.resetSearchForm();
            });

            dispatcher.listenTo(collection, 'search', function() {
                results.render();
            });

            dispatcher.listenTo(collection, 'next', function() {
                results.renderNext();
            });

            dispatcher.listenTo(collection, 'error', function() {
                results.showErrorMessage();
            });
        };
    });
// eslint-disable-next-line no-undef
}(define || RequireJS.define));
