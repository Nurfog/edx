// Generated by CoffeeScript 1.6.1

/*
Instructor Dashboard Tab Manager

The instructor dashboard is broken into sections.

Only one section is visible at a time,
  and is responsible for its own functionality.

NOTE: plantTimeout (which is just setTimeout from util.coffee)
      is used frequently in the instructor dashboard to isolate
      failures. If one piece of code under a plantTimeout fails
      then it will not crash the rest of the dashboard.

NOTE: The instructor dashboard currently does not
      use backbone. Just lots of jquery. This should be fixed.

NOTE: Server endpoints in the dashboard are stored in
      the 'data-endpoint' attribute of relevant html elements.
      The urls are rendered there by a template.

NOTE: For an example of what a section object should look like
      see course_info.coffee

imports from other modules
wrap in (-> ... apply) to defer evaluation
such that the value can be defined later than this assignment (file load order).
*/


(function($) {
  var $active_section, CSS_ACTIVE_SECTION, CSS_IDASH_SECTION, CSS_INSTRUCTOR_CONTENT, CSS_INSTRUCTOR_NAV, HASH_LINK_PREFIX, KEYS, SafeWaiter, activateTab, activateTabPanel, checkForLocationHash, clickListener, keyListener, nextTab, plantTimeout, previousTab, resetTabPanels, resetTabs, sections_have_loaded, setup_instructor_dashboard_sections, std_ajax_err, tabAnalytics, tabs, updateLocationHash,
    _this = this;

  plantTimeout = function() {
    return window.InstructorDashboard.util.plantTimeout.apply(this, arguments);
  };

  std_ajax_err = function() {
    return window.InstructorDashboard.util.std_ajax_err.apply(this, arguments);
  };

  CSS_INSTRUCTOR_CONTENT = 'instructor-dashboard-content-2';

  CSS_ACTIVE_SECTION = 'active-section';

  CSS_IDASH_SECTION = 'idash-section';

  CSS_INSTRUCTOR_NAV = 'instructor-nav';

  HASH_LINK_PREFIX = '#view-';

  $active_section = null;

  KEYS = {
    'left': 37,
    'right': 39,
    'down': 40,
    'up': 38
  };

  SafeWaiter = (function() {

    function SafeWaiter() {
      this.after_handlers = [];
      this.waitFor_handlers = [];
      this.fired = false;
    }

    SafeWaiter.prototype.after = function(f) {
      if (this.fired) {
        return f();
      } else {
        return this.after_handlers.push(f);
      }
    };

    SafeWaiter.prototype.waitFor = function(f) {
      var _this = this;
      if (this.fired) {
        return;
      }
      this.waitFor_handlers.push(f);
      return function() {
        _this.waitFor_handlers = _this.waitFor_handlers.filter(function(g) {
          return g !== f;
        });
        if (_this.waitFor_handlers.length === 0) {
          _this.fired = true;
          _this.after_handlers.map(function(cb) {
            return plantTimeout(0, cb);
          });
        }
        return f.apply(_this, arguments);
      };
    };

    return SafeWaiter;

  })();

  sections_have_loaded = new SafeWaiter;

  $(function() {
    var instructor_dashboard_content;
    instructor_dashboard_content = $("." + CSS_INSTRUCTOR_CONTENT);
    if (instructor_dashboard_content.length > 0) {
      setup_instructor_dashboard_sections(instructor_dashboard_content);
      tabs();
      return true;
    }
  });

  tabs = function() {
    var startPanel, startTab;
    console.log("tabs loaded");
    startTab = $('.' + CSS_INSTRUCTOR_NAV).children('.nav-item').first();
    startPanel = $(startTab).attr('aria-controls');
    checkForLocationHash(startTab, startPanel);
    keyListener();
    return clickListener();
  };

  resetTabs = function() {
    console.log("resettabs");
    $('.' + CSS_INSTRUCTOR_NAV).children('.nav-item').each(function(index, element) {
      var tab;
      tab = $(element);
      return $(tab).attr({
        'aria-selected': 'false',
        'tabindex': '-1'
      }).removeClass(CSS_ACTIVE_SECTION);
    });
    return resetTabPanels();
  };

  resetTabPanels = function() {
    var _this = this;
    console.log("resettabpanels");
    return $('.' + CSS_IDASH_SECTION).each(function(index, element) {
      var panel;
      panel = $(element);
      return $(panel).attr({
        'aria-hidden': 'true',
        'tabindex': '-1'
      }).hide().removeClass(CSS_ACTIVE_SECTION);
    });
  };

  keyListener = function() {
    var _this = this;
    console.log("listening for keys");
    return $('.' + CSS_INSTRUCTOR_NAV).on('keydown', '.nav-item', function(event) {
      var focused, index, key, panel, total;
      key = event.which;
      focused = $(event.currentTarget);
      index = $(focused).parent().find('.nav-item').index(focused);
      total = $(focused).parent().find('.nav-item').size() - 1;
      panel = $(focused).attr('aria-controls');
      switch (key) {
        case KEYS.left:
        case KEYS.up:
          return previousTab(focused, index, total, event);
        case KEYS.right:
        case KEYS.down:
          return nextTab(focused, index, total, event);
      }
    });
  };

  clickListener = function() {
    console.log("listening for mouse");
    return $('.' + CSS_INSTRUCTOR_NAV).on('click', '.nav-item', function(event) {
      var panel, tab;
      tab = $(event.currentTarget);
      panel = $(tab).attr('aria-controls');
      resetTabs();
      return activateTab(tab, panel);
    });
  };

  previousTab = function(focused, index, total, event) {
    var panel, tab;
    console.log("previous tab");
    if (event.altKey || event.shiftKey) {
      true;
    }
    if (index === 0) {
      tab = $(focused).parent().find('.nav-item').last();
    } else {
      tab = $(focused).parent().find('.nav-item:eq(' + index + ')').prev();
    }
    panel = $(tab).attr('aria-controls');
    $(tab).focus();
    activateTab(tab, panel);
    return false;
  };

  nextTab = function(focused, index, total, event) {
    var panel, tab;
    console.log("next tab");
    if (event.altKey || event.shiftKey) {
      true;
    }
    if (index === total) {
      tab = $(focused).parent().find('.nav-item').first();
    } else {
      tab = $(focused).parent().find('.nav-item:eq(' + index + ')').next();
    }
    panel = $(tab).attr('aria-controls');
    $(tab).focus();
    activateTab(tab, panel);
    return false;
  };

  activateTab = function(tab, panel) {
    var section_name;
    console.log("activating tab");
    resetTabs();
    activateTabPanel(panel);
    section_name = $(tab).data('section');
    $(tab).attr({
      'aria-selected': 'true',
      'tabindex': '0'
    }).addClass(CSS_ACTIVE_SECTION);
    tabAnalytics(section_name);
    return updateLocationHash(section_name);
  };

  activateTabPanel = function(panel) {
    console.log("activating tab panel");
    resetTabPanels();
    return $('#' + panel).attr({
      'aria-hidden': 'false',
      'tabindex': '0'
    }).show().addClass(CSS_ACTIVE_SECTION);
  };

  updateLocationHash = function(section_name) {
    console.log("updating hash");
    return location.hash = "" + HASH_LINK_PREFIX + section_name;
  };

  checkForLocationHash = function(startTab, startPanel) {
    var link, panel, rmatch, section_name;
    console.log("checking for hash");
    if (location.hash) {
      if ((new RegExp("^" + HASH_LINK_PREFIX)).test(location.hash)) {
        rmatch = (new RegExp("^" + HASH_LINK_PREFIX + "(.*)")).exec(location.hash);
        section_name = rmatch[1];
        link = $('.' + CSS_INSTRUCTOR_NAV + ' .nav-item').filter("[data-section='" + section_name + "']");
        panel = $(link).attr('aria-controls');
      }
      if (link.length === 1) {
        return activateTab(link, panel);
      } else {
        return activateTab(startTab, startPanel);
      }
    } else {
      return activateTab(startTab, startPanel);
    }
  };

  tabAnalytics = function(section_name) {
    return analytics.pageview("instructor_section:" + section_name);
  };

  setup_instructor_dashboard_sections = function(idash_content) {
    var sections_to_initialize;
    sections_to_initialize = [
      {
        constructor: window.InstructorDashboard.sections.CourseInfo,
        $element: idash_content.find("." + CSS_IDASH_SECTION + "#course_info")
      }, {
        constructor: window.InstructorDashboard.sections.DataDownload,
        $element: idash_content.find("." + CSS_IDASH_SECTION + "#data_download")
      }, {
        constructor: window.InstructorDashboard.sections.ECommerce,
        $element: idash_content.find("." + CSS_IDASH_SECTION + "#e-commerce")
      }, {
        constructor: window.InstructorDashboard.sections.Membership,
        $element: idash_content.find("." + CSS_IDASH_SECTION + "#membership")
      }, {
        constructor: window.InstructorDashboard.sections.StudentAdmin,
        $element: idash_content.find("." + CSS_IDASH_SECTION + "#student_admin")
      }, {
        constructor: window.InstructorDashboard.sections.Extensions,
        $element: idash_content.find("." + CSS_IDASH_SECTION + "#extensions")
      }, {
        constructor: window.InstructorDashboard.sections.Email,
        $element: idash_content.find("." + CSS_IDASH_SECTION + "#send_email")
      }, {
        constructor: window.InstructorDashboard.sections.InstructorAnalytics,
        $element: idash_content.find("." + CSS_IDASH_SECTION + "#instructor_analytics")
      }, {
        constructor: window.InstructorDashboard.sections.Metrics,
        $element: idash_content.find("." + CSS_IDASH_SECTION + "#metrics")
      }, {
        constructor: window.InstructorDashboard.sections.CohortManagement,
        $element: idash_content.find("." + CSS_IDASH_SECTION + "#cohort_management")
      }, {
        constructor: window.InstructorDashboard.sections.Certificates,
        $element: idash_content.find("." + CSS_IDASH_SECTION + "#certificates")
      }
    ];
    if (edx.instructor_dashboard.proctoring !== void 0) {
      sections_to_initialize = sections_to_initialize.concat([
        {
          constructor: edx.instructor_dashboard.proctoring.ProctoredExamAllowanceView,
          $element: idash_content.find("." + CSS_IDASH_SECTION + "#special_exams")
        }, {
          constructor: edx.instructor_dashboard.proctoring.ProctoredExamAttemptView,
          $element: idash_content.find("." + CSS_IDASH_SECTION + "#special_exams")
        }
      ]);
    }
    return sections_to_initialize.map(function(_arg) {
      var $element, constructor;
      constructor = _arg.constructor, $element = _arg.$element;
      return plantTimeout(0, sections_have_loaded.waitFor(function() {
        return new constructor($element);
      }));
    });
  };

}).call(this);
