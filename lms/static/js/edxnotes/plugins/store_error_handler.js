/* eslint-disable-next-line no-shadow-restricted-names, no-unused-vars */
(function(define, undefined) {
    'use strict';

    define(['annotator_1.2.9'], function(Annotator) {
    /**
     * Modifies Annotator.Plugin.Store.prototype._onError to show custom error message
     * if sent by server
     */
        // eslint-disable-next-line no-var
        var originalErrorHandler = Annotator.Plugin.Store.prototype._onError;
        // eslint-disable-next-line consistent-return
        Annotator.Plugin.Store.prototype._onError = function(xhr) {
            // eslint-disable-next-line no-var
            var serverResponse;

            // Try to parse json
            if (xhr.responseText) {
                try {
                    serverResponse = JSON.parse(xhr.responseText);
                } catch (exception) {
                    serverResponse = null;
                }
            }

            // if response includes an error message it will take precedence
            if (serverResponse && serverResponse.error_msg) {
                Annotator.showNotification(serverResponse.error_msg, Annotator.Notification.ERROR);
                // eslint-disable-next-line no-console
                return console.error(Annotator._t('API request failed:') + (" '" + xhr.status + "'"));
            }

            // Delegate to original error handler
            originalErrorHandler(xhr);
        };
    });
// eslint-disable-next-line no-undef
}).call(this, define || RequireJS.define);
