(function(define) {
    'use strict';

    define(['jquery'], function($) {
        // eslint-disable-next-line no-var
        var edxUserCookieUtils = {
            userFromEdxUserCookie: function(edxUserInfoCookieName) {
                // eslint-disable-next-line no-var
                var cookie, user, userCookie;

                cookie = document.cookie.match('(^|;)\\s*' + edxUserInfoCookieName + '\\s*=\\s*([^;]+)');
                userCookie = cookie ? cookie.pop() : $.cookie(edxUserInfoCookieName);

                if (!userCookie) {
                    return {};
                }

                // returns the user object from cookie. Replaces '054' with ',' and removes '\'
                user = userCookie.replace(/\\/g, '').replace(/054/g, ',');
                user = user.substring(1, user.length - 1);
                return JSON.parse(user);
            }
        };

        return edxUserCookieUtils;
    });
// eslint-disable-next-line no-undef
}).call(this, define || RequireJS.define);
