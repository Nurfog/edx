""" Test the behavior of split_mongo/MongoPersistenceBackend """


import unittest
from unittest.mock import patch

import pytest
from pymongo.errors import ConnectionFailure

from xmodule.exceptions import HeartbeatFailure
from xmodule.modulestore.split_mongo.mongo_connection import MongoPersistenceBackend


class TestHeartbeatFailureException(unittest.TestCase):
    """ Test that a heartbeat failure is thrown at the appropriate times """

    @patch('pymongo.MongoClient')
    @patch('pymongo.database.Database')
    def test_heartbeat_retries_on_failure(self, MockDatabase, MockClient):
        # Setup mock client and database
        mock_client = MockClient.return_value
        mock_database = MockDatabase.return_value
        mock_database.admin.command.side_effect = ConnectionFailure('Test')

        useless_conn = MongoPersistenceBackend('useless', 'useless', 'useless')

        # Verify that the heartbeat method raises a HeartbeatFailure
        with pytest.raises(HeartbeatFailure):
            useless_conn.heartbeat()

        # Assert that retries are handled correctly
        self.assertGreater(mock_database.admin.command.call_count, 1)  # Ensure retries happened
