/* eslint-disable-next-line no-shadow-restricted-names, no-unused-vars */
(function(define, undefined) {
    'use strict';

    define([
        'backbone', 'js/edxnotes/models/tab'
    ], function(Backbone, TabModel) {
        // eslint-disable-next-line no-var
        var TabsCollection = Backbone.Collection.extend({
            model: TabModel
        });

        return TabsCollection;
    });
// eslint-disable-next-line no-undef
}).call(this, define || RequireJS.define);
