"""
Content Tagging APIs
"""
from __future__ import annotations

from itertools import groupby

import openedx_tagging.core.tagging.api as oel_tagging
from django.db.models import Q, QuerySet, Exists, OuterRef
from opaque_keys.edx.keys import CourseKey, UsageKey
from openedx_tagging.core.tagging.models import ObjectTag, Taxonomy
from organizations.models import Organization
from xmodule.modulestore.django import modulestore

from .models import ContentObjectTag, TaxonomyOrg
from .types import (
    ContentKey,
    ObjectTagByObjectIdDict,
    TaggedContent,
    TaxonomyDict,
)


def create_taxonomy(
    name: str,
    description: str | None = None,
    enabled=True,
    allow_multiple=True,
    allow_free_text=False,
    orgs: list[Organization] | None = None,
) -> Taxonomy:
    """
    Creates, saves, and returns a new Taxonomy with the given attributes.
    """
    taxonomy = oel_tagging.create_taxonomy(
        name=name,
        description=description,
        enabled=enabled,
        allow_multiple=allow_multiple,
        allow_free_text=allow_free_text,
    )

    if orgs is not None:
        set_taxonomy_orgs(taxonomy=taxonomy, all_orgs=False, orgs=orgs)

    return taxonomy


def set_taxonomy_orgs(
    taxonomy: Taxonomy,
    all_orgs=False,
    orgs: list[Organization] | None = None,
    relationship: TaxonomyOrg.RelType = TaxonomyOrg.RelType.OWNER,
):
    """
    Updates the list of orgs associated with the given taxonomy.

    Currently, we only have an "owner" relationship, but there may be other types added in future.

    When an org has an "owner" relationship with a taxonomy, that taxonomy is available for use by content in that org,
    mies

    If `all_orgs`, then the taxonomy is associated with all organizations, and the `orgs` parameter is ignored.

    If not `all_orgs`, the taxonomy is associated with each org in the `orgs` list. If that list is empty, the
    taxonomy is not associated with any orgs.
    """
    if taxonomy.system_defined:
        raise ValueError("Cannot set orgs for a system-defined taxonomy")

    TaxonomyOrg.objects.filter(
        taxonomy=taxonomy,
        rel_type=relationship,
    ).delete()

    # org=None means the relationship is with "all orgs"
    if all_orgs:
        orgs = [None]
    if orgs:
        TaxonomyOrg.objects.bulk_create(
            [
                TaxonomyOrg(
                    taxonomy=taxonomy,
                    org=org,
                    rel_type=relationship,
                )
                for org in orgs
            ]
        )


def get_taxonomies_for_org(
    enabled=True,
    org_owner: Organization | None = None,
) -> QuerySet:
    """
    Generates a list of the enabled Taxonomies available for the given org, sorted by name.

    We return a QuerySet here for ease of use with Django Rest Framework and other query-based use cases.
    So be sure to use `Taxonomy.cast()` to cast these instances to the appropriate subclass before use.

    If no `org` is provided, then only Taxonomies which are available for _all_ Organizations are returned.

    If you want the disabled Taxonomies, pass enabled=False.
    If you want all Taxonomies (both enabled and disabled), pass enabled=None.
    """
    org_short_name = org_owner.short_name if org_owner else None
    return oel_tagging.get_taxonomies(enabled=enabled).filter(
        Exists(
            TaxonomyOrg.get_relationships(
                taxonomy=OuterRef("pk"),  # type: ignore
                rel_type=TaxonomyOrg.RelType.OWNER,
                org_short_name=org_short_name,
            )
        )
    )


def get_unassigned_taxonomies(enabled=True) -> QuerySet:
    """
    Generate a list of the enabled orphaned Taxomonies, i.e. that do not belong to any
    organization. We don't use `TaxonomyOrg.get_relationships` as that returns
    Taxonomies which are available for all Organizations when no `org` is provided
    """
    return oel_tagging.get_taxonomies(enabled=enabled).filter(
        ~(
            Exists(
                TaxonomyOrg.objects.filter(
                    taxonomy=OuterRef("pk"),
                    rel_type=TaxonomyOrg.RelType.OWNER,
                )
            )
        )
    )


def get_content_tags(
    object_key: ContentKey,
    taxonomy_id: int | None = None,
) -> QuerySet[ContentObjectTag]:
    """
    Generates a list of content tags for a given object.

    Pass taxonomy to limit the returned object_tags to a specific taxonomy.
    """

    tags = oel_tagging.get_object_tags(
        object_id=str(object_key),
        taxonomy_id=taxonomy_id,
        object_tag_class=ContentObjectTag,
    )

    # Add a generic type to get_object_tags to fix this
    return tags  # type: ignore


# FixMe: The following method (tag_content_object) is only used in tasks.py for auto-tagging. To tag object we are
# using oel_tagging.tag_object and checking permissions via rule overrides.
def tag_content_object(
    object_key: ContentKey,
    taxonomy: Taxonomy,
    tags: list,
) -> QuerySet[ContentObjectTag]:
    """
    This is the main API to use when you want to add/update/delete tags from a content object (e.g. an XBlock or
    course).

    It works one "Taxonomy" at a time, i.e. one field at a time, so you can set call it with taxonomy=Keywords,
    tags=["gravity", "newton"] to replace any "Keywords" [Taxonomy] tags on the given content object with "gravity" and
    "newton". Doing so to change the "Keywords" Taxonomy won't affect other Taxonomy's tags (other fields) on the
    object, such as "Language: [en]" or "Difficulty: [hard]".

    If it's a free-text taxonomy, then the list should be a list of tag values.
    Otherwise, it should be a list of existing Tag IDs.

    Raises ValueError if the proposed tags are invalid for this taxonomy.
    Preserves existing (valid) tags, adds new (valid) tags, and removes omitted (or invalid) tags.
    """
    if not taxonomy.system_defined:
        # We require that this taxonomy is linked to the content object's "org" or linked to "all orgs" (None):
        org_short_name = object_key.org  # type: ignore
        if not taxonomy.taxonomyorg_set.filter(Q(org__short_name=org_short_name) | Q(org=None)).exists():
            raise ValueError(f"The specified Taxonomy is not enabled for the content object's org ({org_short_name})")
    oel_tagging.tag_object(
        taxonomy=taxonomy,
        tags=tags,
        object_id=str(object_key),
        object_tag_class=ContentObjectTag,
    )
    return get_content_tags(object_key, taxonomy_id=taxonomy.id)


def get_content_tags_for_object(
    content_key: ContentKey,
    include_children: bool,
) -> tuple[TaggedContent, TaxonomyDict]:
    """
    Returns the object with the tags associated with it. If include_children is True, then it will also include
    the children of the object and their tags.
    """

    def _get_object_tags(content_key: ContentKey, include_children: bool) -> QuerySet[ObjectTag]:
        """
        Return the tags for the object and its children using a single db query.
        """
        content_key_str = str(content_key)
        if not include_children:
            return ObjectTag.objects.filter(object_id=content_key_str).select_related("tag__taxonomy").all()

        # We use a block_id_prefix (i.e. the modified course id) to get the tags for the children of the Content
        # (course) in a single db query.
        # ToDo: Add support for other content types (like LibraryContent and LibraryBlock)
        if isinstance(content_key, UsageKey):
            course_key_str = str(content_key.course_key)
            block_id_prefix = course_key_str.replace("course-v1:", "block-v1:", 1)
        elif isinstance(content_key, CourseKey):
            course_key_str = str(content_key)
            block_id_prefix = str(content_key).replace("course-v1:", "block-v1:", 1)
        else:
            raise NotImplementedError(f"Invalid content_key: {type(content_key)} -> {content_key}")

        return ObjectTag.objects.filter(Q(object_id__startswith=block_id_prefix) | Q(object_id=course_key_str)) \
            .select_related("tag__taxonomy").all()

    def _group_object_tags_by_objectid_taxonomy(
        all_object_tags: list[ObjectTag]
    ) -> tuple[ObjectTagByObjectIdDict, TaxonomyDict]:
        """
        Returns a tuple with a dictionary of grouped object tags for all blocks and a dictionary of taxonomies.
        """

        groupedObjectTags: ObjectTagByObjectIdDict = {}
        taxonomies: TaxonomyDict = {}

        for object_id, block_tags in groupby(all_object_tags, lambda x: x.object_id):
            groupedObjectTags[object_id] = {}
            for taxonomy_id, taxonomy_tags in groupby(block_tags, lambda x: x.tag.taxonomy_id):
                object_tags_list = list(taxonomy_tags)
                groupedObjectTags[object_id][taxonomy_id] = object_tags_list

                if taxonomy_id not in taxonomies:
                    # ToDo: Change name -> export_id after done:
                    # - https://github.com/openedx/modular-learning/issues/183
                    taxonomies[taxonomy_id] = object_tags_list[0].tag.taxonomy

        return groupedObjectTags, taxonomies

    def _get_object_with_tags(
        content_key: ContentKey,
        include_children: bool,
        objectTagCache: ObjectTagByObjectIdDict,
        store
    ) -> TaggedContent:
        """
        Returns the object with the tags associated with it. If include_children is True, then it will also include
        the children of the object and their tags.
        """
        if isinstance(content_key, CourseKey):
            xblock = store.get_course(content_key)
        elif isinstance(content_key, UsageKey):
            xblock = store.get_item(content_key)
        else:
            raise NotImplementedError(f"Invalid content_key: {type(content_key)} -> {content_key}")

        tagged_xblock = TaggedContent(
            xblock=xblock,
            object_tags=objectTagCache.get(str(content_key), {}),
            children=None,
        )

        if not include_children:
            return tagged_xblock

        blocks = [tagged_xblock]

        while blocks:
            block = blocks.pop()
            block.children = []

            if block.xblock.has_children:
                for child_id in block.xblock.children:
                    child = TaggedContent(
                        xblock=store.get_item(child_id),
                        object_tags=objectTagCache.get(str(child_id), {}),
                        children=None,
                    )
                    block.children.append(child)

                    blocks.append(child)

        return tagged_xblock

    store = modulestore()

    all_blocks_tag_records = list(_get_object_tags(content_key, include_children))
    objectTagCache, taxonomies = _group_object_tags_by_objectid_taxonomy(all_blocks_tag_records)

    return _get_object_with_tags(content_key, include_children, objectTagCache, store), taxonomies


# Expose the oel_tagging APIs

get_taxonomy = oel_tagging.get_taxonomy
get_taxonomies = oel_tagging.get_taxonomies
get_tags = oel_tagging.get_tags
get_object_tag_counts = oel_tagging.get_object_tag_counts
delete_object_tags = oel_tagging.delete_object_tags
resync_object_tags = oel_tagging.resync_object_tags
