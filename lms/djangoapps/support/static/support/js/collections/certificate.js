(function(define) {
    'use strict';

    define(['backbone', 'support/js/models/certificate'],
        function(Backbone, CertModel) {
            return Backbone.Collection.extend({
                model: CertModel,

                initialize: function(options) {
                    this.userFilter = options.userFilter || '';
                    this.courseFilter = options.courseFilter || '';
                },

                setUserFilter: function(userFilter) {
                    this.userFilter = userFilter;
                },

                setCourseFilter: function(courseFilter) {
                    this.courseFilter = courseFilter;
                },

                url: function() {
                    // eslint-disable-next-line no-var
                    var url = '/certificates/search?user=' + this.userFilter;
                    if (this.courseFilter) {
                        url += '&course_id=' + this.courseFilter;
                    }
                    return url;
                }
            });
        });
// eslint-disable-next-line no-undef
}).call(this, define || RequireJS.define);
