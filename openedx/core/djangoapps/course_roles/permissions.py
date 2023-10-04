from enum import Enum, unique



@unique
class CourseRolesPermission(Enum):
    MANAGE_CONTENT = "manage_content"
    MANAGE_COURSE_SETTINGS = "manage_course_settings"
    MANAGE_ADVANCED_SETTINGS = "manage_advanced_settings"
    VIEW_COURSE_SETTINGS = "view_course_settings"
    VIEW_ALL_CONTENT = "view_all_content"
    VIEW_ONLY_LIVE_PUBLISHED_CONTENT = "view_only_live_published_content"
    VIEW_ALL_PUBLISHED_CONTENT = "view_all_published_content"
    ACCESS_INSTRUCTOR_DASHBOARD = "access_instructor_dashboard"
    ACCESS_DATA_DOWNLOADS = "access_data_downloads"
    MANAGE_GRADES = "manage_grades"
    VIEW_GRADEBOOK = "view_gradebook"
    MANAGE_ALL_USERS = "manage_all_users"
    MANAGE_USERS_EXCEPT_ADMIN_AND_STAFF = "manage_users_except_admin_and_staff"
    MANAGE_DISCUSSION_MODERATORS = "manage_discussion_moderators"
    MANAGE_COHORTS = "manage_cohorts"
    MANAGE_STUDENTS = "manage_students"
    MODERATE_DISCUSSION_FORUMS = "moderate_discussion_forums"
    MODERATE_DISCUSSION_FORUMS_FOR_A_COHORT = "moderate_discussion_forums_for_a_cohort"
    MANAGE_CERTIFICATES = "manage_certificates"
    MANAGE_LIBRARIES = "manage_libraries"
    GENERAL_MASQUERADING = "general_masquerading"
    SPECIFIC_MASQUERADING = "specific_masquerading"
