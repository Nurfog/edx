"""
XBlock runtime services for LibraryContentModule
"""
import hashlib

import six
from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from opaque_keys.edx.keys import UsageKey
from opaque_keys.edx.locator import LibraryLocator, LibraryUsageLocator, LibraryUsageLocatorV2, BlockUsageLocator
from openedx.core.djangoapps.content_libraries import api as library_api
from openedx.core.djangoapps.xblock.api import load_block
from search.search_engine_base import SearchEngine
from student.auth import has_studio_write_access
from xblock.fields import Scope
from xmodule.capa_module import ProblemBlock
from xmodule.library_content_module import ANY_CAPA_TYPE_VALUE
from xmodule.modulestore import ModuleStoreEnum
from xmodule.modulestore.exceptions import ItemNotFoundError


def normalize_key_for_search(library_key):
    """ Normalizes library key for use with search indexing """
    return library_key.replace(version_guid=None, branch=None)


class LibraryToolsService(object):
    """
    Service that allows LibraryContentModule to interact with libraries in the
    modulestore.
    """
    def __init__(self, modulestore, user_id):
        self.store = modulestore
        self.user_id = user_id

    def _get_library(self, library_key):
        """
        Given a library key like "library-v1:ProblemX+PR0B", return the
        'library' XBlock with meta-information about the library.

        A specific version may be specified.

        Returns None on error.
        """
        if not isinstance(library_key, LibraryLocator):
            library_key = LibraryLocator.from_string(library_key)

        try:
            return self.store.get_library(
                library_key, remove_version=False, remove_branch=False, head_validation=False
            )
        except ItemNotFoundError:
            return None

    def get_library_version(self, lib_key):
        """
        Get the version (an ObjectID) of the given library.
        Returns None if the library does not exist.
        """
        library = self._get_library(lib_key)
        if library:
            # We need to know the library's version so ensure it's set in library.location.library_key.version_guid
            assert library.location.library_key.version_guid is not None
            return library.location.library_key.version_guid
        return None

    def create_block_analytics_summary(self, course_key, block_keys):
        """
        Given a CourseKey and a list of (block_type, block_id) pairs,
        prepare the JSON-ready metadata needed for analytics logging.

        This is [
            {"usage_key": x, "original_usage_key": y, "original_usage_version": z, "descendants": [...]}
        ]
        where the main list contains all top-level blocks, and descendants contains a *flat* list of all
        descendants of the top level blocks, if any.
        """
        def summarize_block(usage_key):
            """ Basic information about the given block """
            orig_key, orig_version = self.store.get_block_original_usage(usage_key)
            return {
                "usage_key": six.text_type(usage_key),
                "original_usage_key": six.text_type(orig_key) if orig_key else None,
                "original_usage_version": six.text_type(orig_version) if orig_version else None,
            }

        result_json = []
        for block_key in block_keys:
            key = course_key.make_usage_key(*block_key)
            info = summarize_block(key)
            info['descendants'] = []
            try:
                block = self.store.get_item(key, depth=None)  # Load the item and all descendants
                children = list(getattr(block, "children", []))
                while children:
                    child_key = children.pop()
                    child = self.store.get_item(child_key)
                    info['descendants'].append(summarize_block(child_key))
                    children.extend(getattr(child, "children", []))
            except ItemNotFoundError:
                pass  # The block has been deleted
            result_json.append(info)
        return result_json

    def _problem_type_filter(self, library, capa_type):
        """ Filters library children by capa type"""
        search_engine = SearchEngine.get_search_engine(index="library_index")
        if search_engine:
            filter_clause = {
                "library": six.text_type(normalize_key_for_search(library.location.library_key)),
                "content_type": ProblemBlock.INDEX_CONTENT_TYPE,
                "problem_types": capa_type
            }
            search_result = search_engine.search(field_dictionary=filter_clause)
            results = search_result.get('results', [])
            return [LibraryUsageLocator.from_string(item['data']['id']) for item in results]
        else:
            return [key for key in library.children if self._filter_child(key, capa_type)]

    def _filter_child(self, usage_key, capa_type):
        """
        Filters children by CAPA problem type, if configured
        """
        if usage_key.block_type != "problem":
            return False

        descriptor = self.store.get_item(usage_key, depth=0)
        assert isinstance(descriptor, ProblemBlock)
        return capa_type in descriptor.problem_types

    def can_use_library_content(self, block):
        """
        Determines whether a modulestore holding a course_id supports libraries.
        """
        return self.store.check_supports(block.location.course_key, 'copy_from_template')

    def update_children(self, dest_block, user_perms=None, version=None):
        """
        This method is to be used when the library that a LibraryContentModule
        references has been updated. It will re-fetch all matching blocks from
        the libraries, and copy them as children of dest_block. The children
        will be given new block_ids, but the definition ID used should be the
        exact same definition ID used in the library.

        This method will update dest_block's 'source_library_version' field to
        store the version number of the libraries used, so we easily determine
        if dest_block is up to date or not.
        """
        if user_perms and not user_perms.can_write(dest_block.location.course_key):
            raise PermissionDenied()

        if not dest_block.source_library_id:
            dest_block.source_library_version = ""
            return

        source_blocks = []
        library_key = dest_block.source_library_key
        if version:
            library_key = library_key.replace(branch=ModuleStoreEnum.BranchName.library, version_guid=version)
        library = self._get_library(library_key)
        if library is None:
            raise ValueError("Requested library {0} not found.".format(library_key))
        if user_perms and not user_perms.can_read(library_key):
            raise PermissionDenied()
        filter_children = (dest_block.capa_type != ANY_CAPA_TYPE_VALUE)
        if filter_children:
            # Apply simple filtering based on CAPA problem types:
            source_blocks.extend(self._problem_type_filter(library, dest_block.capa_type))
        else:
            source_blocks.extend(library.children)

        with self.store.bulk_operations(dest_block.location.course_key):
            dest_block.source_library_version = str(library.location.library_key.version_guid)
            self.store.update_item(dest_block, self.user_id)
            head_validation = not version
            dest_block.children = self.store.copy_from_template(
                source_blocks, dest_block.location, self.user_id, head_validation=head_validation
            )
            # ^-- copy_from_template updates the children in the DB
            # but we must also set .children here to avoid overwriting the DB again

    def list_available_libraries(self):
        """
        List all known libraries.
        Returns tuples of (LibraryLocator, display_name)
        """
        return [
            (lib.location.library_key.replace(version_guid=None, branch=None), lib.display_name)
            for lib in self.store.get_library_summaries()
        ]

    def import_as_children(self, dest_block, blockstore_block_ids):
        """
        Given an ordered list of IDs in a blockstore-based learning context
        (usually a content library), import them into modulestore as the new
        children of dest_block. If dest_block already has children, they'll be
        replaced with the imported children.

        This is only used by LibrarySourcedBlock. It should verify first that
        the number of block IDs is reasonable.
        """
        dest_key = dest_block.scope_ids.usage_id
        if not isinstance(dest_key, BlockUsageLocator):
            raise TypeError("import_as_children can only import into modulestore courses.")
        if self.user_id is None:
            raise ValueError("Cannot check user permissions - LibraryTools user_id is None")
        if len(set(blockstore_block_ids)) != len(blockstore_block_ids):
            # We don't support importing the exact same block twice because it would break the way we generate new IDs
            # for each block and then overwrite existing copies of blocks when re-importing the same blocks.
            raise ValueError("One or more library component IDs is a duplicate.")

        dest_course_key = dest_key.context_key
        user = User.objects.get(id=self.user_id)
        if not has_studio_write_access(user, dest_course_key):
            raise PermissionDenied()

        # Read all the blocks; this will also confirm the user has permission to read them.
        # (This could be slow and use lots of memory, except for the fact that LibrarySourcedBlock which calls this
        # should be limiting the number of blocks to a reasonable limit. We load them all now instead of one at a
        # time in order to raise any errors before we start actually copying blocks over.)
        orig_blocks = [load_block(UsageKey.from_string(key), user) for key in blockstore_block_ids]

        with self.store.bulk_operations(dest_course_key):
            # As we go, build a set of the IDs of the new children,
            # so we can delete any existing children that aren't updated.
            child_ids_updated = set()

            def do_import(source_block, dest_parent_key):
                """ Recursively import a blockstore block and its children """
                source_key = source_block.scope_ids.usage_id
                # Deterministically generate a new ID for this block 
                new_block_id = (
                    dest_parent_key.block_id[:10] + '-' + hashlib.sha1(str(source_key).encode('utf-8')).hexdigest()[:10]
                )
                new_block_key = dest_parent_key.context_key.make_usage_key(source_key.block_type, new_block_id)

                try:
                    new_block = self.store.get_item(new_block_key)
                    if new_block.parent != dest_parent_key:
                        raise ValueError(
                            "Expected existing block {} to be a child of {} but instead it's a child of {}".format(
                                new_block_key, dest_parent_key, new_block.parent,
                            )
                        )
                except ItemNotFoundError:
                    new_block = self.store.create_child(
                        user_id=self.user_id,
                        parent_usage_key=dest_parent_key,
                        block_type=source_key.block_type,
                        block_id=new_block_id,
                    )

                # Prepare a list of this block's static assets; any that are referenced as /static/foo.png etc. (the
                # recommended way for referencing assets) will stop working unless we rewrite the URL or copied the
                # the assets into the course. Since blockstore namespaces assets to each block but modulestore dumps all
                # of a course's asset files into a common namespace, it's not a good idea to copy the files into the
                # course's static asset store (contentstore) because we may get conflicts (same asset filename used for
                # different library blocks or same asset filename used in a library block as in the destination course)
                if isinstance(source_key, LibraryUsageLocatorV2):
                    all_assets = library_api.get_library_block_static_asset_files(source_key)
                else:
                    all_assets = []

                for field_name, field in source_block.fields.items():
                    if field.scope not in (Scope.settings, Scope.content):
                        continue  # Only copy authored field data
                    if field.is_set_on(source_block) or field.is_set_on(new_block):
                        field_value = getattr(source_block, field_name)
                        if isinstance(field_value, str):
                            # If this is a string field (which may also be JSON/XML data), rewrite /static/... URLs to
                            # point to blockstore, so the runtime doesn't try to load the assets from contentstore which
                            # doesn't have them.
                            for asset in all_assets:
                                field_value = field_value.replace('/static/{}'.format(asset.path), asset.url)
                        setattr(new_block, field_name, field_value)
                new_block.save()
                self.store.update_item(new_block, self.user_id)

                # Recursively import children
                if new_block.has_children:
                    # Delete any children that the new block has since we'll be replacing them all anyways, and want to
                    # Ensure that if a grandchild block was deleted from the source library it will get deleted from the
                    # destination course during this update.
                    for existing_child_key in new_block.children:
                        self.store.delete_item(existing_child_key, self.user_id)
                    # Now import the children
                    for child in source_block.get_children():
                        do_import(child, new_block_key)

                return new_block_key

            # Now actually do the import, making each block in 'orig_blocks' become a child of dest_block
            for block in orig_blocks:
                new_block_id = do_import(block, dest_key)
                child_ids_updated.add(new_block_id)
            # Remove any existing children that are no longer wanted
            existing_children_to_delete = set(dest_block.children) - child_ids_updated
            for old_child_id in existing_children_to_delete:
                self.store.delete_item(old_child_id, self.user_id)

        # If this was called from a handler, it will save dest_block at the end, so we must update
        # dest_block.children to avoid it saving the old value of children and deleting the new children.
        dest_block.children = self.store.get_item(dest_key).children
