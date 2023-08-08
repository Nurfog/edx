// Backbone.js Application Collection: Certificate Signatories

// eslint-disable-next-line no-undef
define([
    'backbone',
    'js/certificates/models/signatory'
],
function(Backbone, Signatory) {
    'use strict';

    // eslint-disable-next-line no-var
    var SignatoryCollection = Backbone.Collection.extend({
        model: Signatory
    });
    return SignatoryCollection;
});
