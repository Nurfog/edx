Response Code and Header
**************************

.. code-block:: json

    HTTP 200 OK
    Allow: GET
    Content-Type: application/json
    Vary: Accept

Response Body
**************************

.. code-block:: json

    {
        "count": 123,
        "next": "https://example.edx.org/api/v1/courses/?offset=60",
        "previous": "https://example.edx.org/api/v1/courses/?offset=20",
        "results": [
            {
                "key": "example_course_key",
                "title": "Title of the Course",
                "short_description": "Short description of course content",
                "full_description": "Longer, more detailed description of course content.",
                "level_type": "Introductory",
                "subjects": [
                    {
                        "name": "Name of subject"
                    }
                ],
                "prerequisites": [],
                "expected_learning_items": [],
                "image": [
                    {
                        "src": "https://example.com/directory/course_image.jpg",
                        "description": "Example image for the Example Title course",
                        "height": "300",
                        "width": "400"
                     }
                ],
                "video": [
                    {
                        "src": "http://www.youtube.com/watch?v=abcdefghijk",
                        "description": null,
                        "image": null
                    }
                ],
                "owners": [
                    {
                        "key": "example_institution_key",
                        "name": "Example Institution",
                        "description": null,
                        "logo_image": [
                            {
                            "src": "https://example.com/directory/institution_logo.jpg",
                            "description": null
                            "height": "200",
                            "width": "200"
                            }
                        ],
                        "homepage_url": null
                    }
                ],
                "sponsors": [],
                "modified": "YYYY-MM-DDTHH:MM:SS.SSSSSSZ",
                "course_runs": [
                    {
                        "course": "course_number",
                        "key": "example_course_key",
                        "title": "Title of the Course",
                        "short_description": "Short description of course content",
                        "full_description": "Longer, more detailed description of course content",
                        "start": "YYYY-MM-DDTHH:MM:SSZ",
                        "end": "YYYY-MM-DDTHH:MM:SSZ",
                        "enrollment_start": "YYYY-MM-DDTHH:MM:SSZ",
                        "enrollment_end": "YYYY-MM-DDTHH:MM:SSZ",
                        "announcement": null,
                        "image": [
                            {
                            "src": "https://example.com/directory/course_image.jpg",
                            "description": null,
                            "height": "200",
                            "width": "300"
                            },
                        ]
                        "video": null,
                        "seats": [
                            {
                            "type": "credit",
                            "price": "100.00",
                            "currency": "USD",
                            "upgrade_deadline": "YYYY-MM-DDTHH:MM:SSZ",
                            "credit_provider": "example institution",
                            "credit_hours": 3
                            }
                        ],
                        "content_language": null,
                        "transcript_languages": [],
                        "instructors": [],
                        "staff": [
                            {
                            "key": "staff_key",
                            "name": "Staff Member Name",
                            "title": "Staff Member Title",
                            "bio": "Example staff member bio.",
                            "profile_image": {
                                "src": "https://example.com/image/staff_member_name.png",
                                "description": null,
                                "height": "150",
                                "width": "150"
                            }
                        ],
                        "pacing_type": "instructor_paced",
                        "min_effort": null,
                        "max_effort": null,
                        "modified": "YYYY-MM-DDTHH:MM:SS.SSSSSSZ"
                    }
                ],
                "marketing_url": "https://example.org/url_for_marketing_materials"
            }
        ]
    }
