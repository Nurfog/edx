/**
 *
 * A helper function to utilize DateUtils quickly in display templates.
 *
 * @param: {string} data-datetime A pre-localized datetime string, assumed to be in UTC.
 * @param: {string} lang The user's preferred language.
 * @param: {string} data-timezone (optional) A user-set timezone preference.
 * @param: {object} data-format (optional) a format constant as defined in DataUtil.dateFormatEnum.
 * @param: {string} data-string (optional) a string for parsing through StringUtils after localizing
 * datetime
 *
 * @return: {string} a user-time, localized, formatted datetime string
 *
 */

(function(define) {
    'use strict';

    define([
        'jquery',
        'edx-ui-toolkit/js/utils/date-utils',
        'edx-ui-toolkit/js/utils/string-utils'
    ], function($, DateUtils, StringUtils) {
        // eslint-disable-next-line no-var
        var DateUtilFactory;
        // eslint-disable-next-line no-var
        var localizedTime;
        // eslint-disable-next-line no-var
        var stringHandler;
        // eslint-disable-next-line no-var
        var displayDatetime;
        // eslint-disable-next-line no-var
        var isValid;
        // eslint-disable-next-line no-var
        var transform;
        // eslint-disable-next-line no-var
        var dueDateFormat;
        // eslint-disable-next-line no-var
        var dateFormat;

        dueDateFormat = Object.freeze({
            '%Y-%d-%m': 'YYYY, D MMM HH[:]mm z', // example: 2018, 01 Jan 15:30 UTC
            '%m-%d-%Y': 'MMM D, YYYY HH[:]mm z', // example: Jan 01, 2018 15:30 UTC
            '%d-%m-%Y': 'D MMM YYYY HH[:]mm z', // example: 01 Jan, 2018 15:30 UTC
            '%Y-%m-%d': 'YYYY, MMM D HH[:]mm z' // example: 2018, Jan 01 15:30 UTC
        });

        transform = function(iterationKey) {
            // eslint-disable-next-line no-var
            var context;
            $(iterationKey).each(function() {
                if (isValid($(this).data('datetime'))) {
                    dateFormat = DateUtils.dateFormatEnum[$(this).data('format')];
                    if (typeof dateFormat === 'undefined') {
                        dateFormat = dueDateFormat[$(this).data('format')];
                    }
                    context = {
                        datetime: $(this).data('datetime'),
                        timezone: $(this).data('timezone'),
                        language: $(this).data('language'),
                        format: dateFormat
                    };
                    displayDatetime = stringHandler(
                        localizedTime(context),
                        $(this).data('string'),
                        $(this).data('datetoken')
                    );
                    $(this).text(displayDatetime);
                } else {
                    displayDatetime = stringHandler(
                        $(this).data('string')
                    );
                    $(this).text(displayDatetime);
                }
            });
        };

        localizedTime = function(context) {
            return DateUtils.localize(context);
        };

        stringHandler = function(localTimeString, containerString, token) {
            // eslint-disable-next-line no-var
            var returnString;
            // eslint-disable-next-line no-var
            var interpolateDict = {};
            // eslint-disable-next-line no-var
            var dateToken;
            if (isValid(token)) {
                dateToken = token;
            } else {
                dateToken = 'date';
            }
            interpolateDict[dateToken] = localTimeString;

            if (isValid(containerString)) {
                returnString = StringUtils.interpolate(
                    containerString,
                    interpolateDict
                );
            } else {
                returnString = localTimeString;
            }
            return returnString;
        };

        isValid = function(candidateVariable) {
            return candidateVariable !== undefined
                && candidateVariable !== ''
                && candidateVariable !== 'Invalid date'
                && candidateVariable !== 'None';
        };
        DateUtilFactory = {
            transform: transform,
            stringHandler: stringHandler
        };
        return DateUtilFactory;
    });
// eslint-disable-next-line no-undef
}).call(this, define || RequireJS.define);
