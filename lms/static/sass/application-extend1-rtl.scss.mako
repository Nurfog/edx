## NOTE: This Sass infrastructure is redundant, but needed in order to address an IE9 rule limit within CSS - http://blogs.msdn.com/b/ieinternals/archive/2011/05/14/10164546.aspx


// lms - css application architecture (platform)
// ====================

// libs and resets *do not edit*
@import 'bourbon/bourbon'; // lib - bourbon

// BASE  *default edX offerings*
// ====================

// base - utilities
@import 'base/variables';
@import 'base/reset';
@import 'base/mixins';

## THEMING
## -------
## Set up this file to import an edX theme library if the environment
## indicates that a theme should be used. The assumption is that the
## theme resides outside of this main edX repository, in a directory
## called themes/<theme-name>/, with its base Sass file in
## themes/<theme-name>/static/sass/_<theme-name>.scss. That one entry
## point can be used to @import in as many other things as needed.
% if env['FEATURES'].get("USE_CUSTOM_THEME", False):
  // import theme's Sass overrides
  @import '${env.get('THEME_NAME')}';
% endif

@import 'base/base_rtl';

// base - assets
@import 'base/font_face';
@import 'base/extends';
@import 'base/animations';

// base - starter
@import 'base/base_rtl';

// base - elements
@import 'elements/typography';
@import 'elements/controls';

// shared - platform
@import 'multicourse/home';
@import 'multicourse/dashboard_rtl';
@import 'multicourse/account_rtl';
@import 'multicourse/courses';
@import 'multicourse/course_about';
@import 'multicourse/jobs';
@import 'multicourse/media-kit';
@import 'multicourse/about_pages';
@import 'multicourse/press_release';
@import 'multicourse/password_reset';
@import 'multicourse/error-pages';
@import 'multicourse/help';
@import 'multicourse/edge';

## NOTE: needed here for cascade and dependency purposes, but not a great permanent solution
@import 'shame'; // shame file - used for any bad-form/orphaned scss that knowingly violate edX FED architecture/standards (see - http://csswizardry.com/2013/04/shame-css/)
