(function(define) {
    'use strict';

    define(['backbone', 'js/discovery/models/search_state', 'js/discovery/collections/filters',
        'js/discovery/views/search_form', 'js/discovery/views/courses_listing',
        'js/discovery/views/filter_bar', 'js/discovery/views/refine_sidebar'],
    function(Backbone, SearchState, Filters, SearchForm, CoursesListing, FilterBar, RefineSidebar) {
        return function(meanings, searchQuery, userLanguage, userTimezone) {
            /* eslint-disable-next-line no-undef, no-var */
            var dispatcher = _.extend({}, Backbone.Events);
            // eslint-disable-next-line no-var
            var search = new SearchState();
            // eslint-disable-next-line no-var
            var filters = new Filters();
            // eslint-disable-next-line no-var
            var form = new SearchForm();
            // eslint-disable-next-line no-var
            var filterBar = new FilterBar({collection: filters});
            // eslint-disable-next-line no-var
            var refineSidebar = new RefineSidebar({
                collection: search.discovery.facetOptions,
                meanings: meanings
            });
            // eslint-disable-next-line no-var
            var listing;
            // eslint-disable-next-line no-var
            var courseListingModel = search.discovery;
            courseListingModel.userPreferences = {
                userLanguage: userLanguage,
                userTimezone: userTimezone
            };
            listing = new CoursesListing({model: courseListingModel});

            dispatcher.listenTo(form, 'search', function(query) {
                filters.reset();
                form.showLoadingIndicator();
                search.performSearch(query, filters.getTerms());
            });

            dispatcher.listenTo(refineSidebar, 'selectOption', function(type, query, name) {
                form.showLoadingIndicator();
                if (filters.get(type)) {
                    // eslint-disable-next-line no-use-before-define
                    removeFilter(type);
                } else {
                    filters.add({type: type, query: query, name: name});
                    search.refineSearch(filters.getTerms());
                }
            });

            // eslint-disable-next-line no-use-before-define
            dispatcher.listenTo(filterBar, 'clearFilter', removeFilter);

            dispatcher.listenTo(filterBar, 'clearAll', function() {
                form.doSearch('');
            });

            dispatcher.listenTo(listing, 'next', function() {
                search.loadNextPage();
            });

            dispatcher.listenTo(search, 'next', function() {
                listing.renderNext();
            });

            dispatcher.listenTo(search, 'search', function(query, total) {
                if (total > 0) {
                    form.showFoundMessage(total);
                    if (query) {
                        filters.add(
                            // eslint-disable-next-line no-use-before-define
                            {type: 'search_query', query: query, name: quote(query)},
                            {merge: true}
                        );
                    }
                } else {
                    form.showNotFoundMessage(query);
                    filters.reset();
                }
                form.hideLoadingIndicator();
                listing.render();
                refineSidebar.render();
            });

            dispatcher.listenTo(search, 'error', function() {
                form.showErrorMessage(search.errorMessage);
                form.hideLoadingIndicator();
            });

            // kick off search on page refresh
            form.doSearch(searchQuery);

            function removeFilter(type) {
                form.showLoadingIndicator();
                filters.remove(type);
                if (type === 'search_query') {
                    form.doSearch('');
                } else {
                    search.refineSearch(filters.getTerms());
                }
            }

            function quote(string) {
                return '"' + string + '"';
            }
        };
    });
// eslint-disable-next-line no-undef
}(define || RequireJS.define));
