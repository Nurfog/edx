"""
:class:`~xblock.field_data.FieldData` subclasses used by the LMS
"""

from xblock.field_data import ReadOnlyFieldData, SplitFieldData
from xblock.fields import Scope, RemoteScope
from xblock.runtime import KeyValueStore

from courseware.model_data import FieldDataCache


class LmsFieldData(SplitFieldData):
    """
    A :class:`~xblock.field_data.FieldData` that
    reads all UserScope.ONE and UserScope.ALL fields from `student_data`
    and all UserScope.NONE fields from `authored_data`. It also prevents
    writing to `authored_data`.
    """
    def __init__(self, authored_data, student_data, shared_data=None):
        # Make sure that we don't repeatedly nest LmsFieldData instances
        if isinstance(authored_data, LmsFieldData):
            authored_data = authored_data._authored_data  # pylint: disable=protected-access
        else:
            authored_data = ReadOnlyFieldData(authored_data)

        self._authored_data = authored_data
        self._student_data = student_data

        super(LmsFieldData, self).__init__({
            Scope.content: authored_data,
            Scope.settings: authored_data,
            Scope.parent: authored_data,
            Scope.children: authored_data,
            Scope.user_state_summary: student_data,
            Scope.user_state: student_data,
            Scope.user_info: student_data,
            Scope.preferences: student_data,
            RemoteScope.individual: shared_data
        })

    def __repr__(self):
        return "LmsFieldData{!r}".format((self._authored_data, self._student_data))

class SharedFieldData(FieldData):
    """Summary"""
    def __init__(self, course_id, user, **kwargs):
        """Summary
        
        Args:
            course_id (TYPE): Description
            user (TYPE): Description
            **kwargs: Description
        
        Deleted Parameters:
            data_cache (TYPE): Description
        """
        super(SharedFieldData, self).__init__(**kwargs)
        self._cache = FieldDataCache([], course_id, user)

    def _build_kvs_key(block, name):
        """Summary
        
        Args:
            block (TYPE): Description
            name (TYPE): Description
        
        Returns:
            TYPE: Description
        
        Deleted Parameters:
            scope_id (TYPE): Description
        """
        ### TODO: finish this
        ### There is a method in KvsFieldData can build more generalized key, but it requires an xblock as input
        return KeyValueStore.Key(
            scope=block.fields[name],
            user_id=user_id, 
            block_scope_id=scope_ids.usage_id,
            field_name=name,
            block_family=block.entry_point)

    def set(self, block, name, values):
        """Summary
        
        Returns:
            TYPE: Description
        
        Args:
            block (TYPE): Description
            name (TYPE): Description
            values (TYPE): Description
        """
        pass

    def get(self, block, name):
        """Summary
        
        Args:
            block (TYPE): Description
            name (TYPE): Description
        
        Returns:
            TYPE: Description
        
        Deleted Parameters:
            scope_id (TYPE): Description
        """
        kvs_key = self._build_kvs_key(block, name)
        shared_data = self._cache.get(key=kvs_key, remote=True)
        return shared_data

    def has(self, block, name):
        """Summary
        
        Args:
            block (TYPE): Description
            name (TYPE): Description
        
        Returns:
            TYPE: Description
        """
        pass

    def delete(self, block, name):
        """Summary
        
        Args:
            block (TYPE): Description
            name (TYPE): Description
        
        Returns:
            TYPE: Description
        """
        pass
