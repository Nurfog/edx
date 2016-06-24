"""
Module for a collection of BlockStructureTransformers.
"""
from logging import getLogger

from .exceptions import TransformerException
from .transformer_registry import TransformerRegistry


logger = getLogger(__name__)  # pylint: disable=C0103


class BlockStructureTransformers(object):
    """
    The BlockStructureTransformers class encapsulates an ordered list of block
    structure transformers.  It uses the Transformer Registry to verify the
    the registration status of added transformers and to collect their data.
    It provides aggregate functionality for collection and ordered
    transformation of the transformers.

    Clients are expected to access the list of transformers through the
    class' interface rather than directly.
    """
    def __init__(self, transformers=None, usage_info=None):
        """
        Arguments:
            transformers ([BlockStructureTransformer]) - List of transformers
                to add to the collection.

            usage_info (any negotiated type) - A usage-specific object
                that is passed to the block_structure and forwarded to all
                requested Transformers in order to apply a
                usage-specific transform. For example, an instance of
                usage_info would contain a user object for which the
                transform should be applied.

        Raises:
            TransformerException - if any transformer is not registered in the
                Transformer Registry.
        """
        self.usage_info = usage_info
        self._transformers = []
        if transformers:
            self.__iadd__(transformers)

    def __iadd__(self, transformers):
        """
        Adds the given transformers to the collection.

        Args:
            transformers ([BlockStructureTransformer]) - List of transformers
                to add to the collection.

        Raises:
            TransformerException - if any transformer is not registered in the
                Transformer Registry.
        """
        unregistered_transformers = TransformerRegistry.find_unregistered(transformers)
        if unregistered_transformers:
            raise TransformerException(
                "The following requested transformers are not registered: {}".format(unregistered_transformers)
            )

        self._transformers.extend(transformers)
        return self

    @classmethod
    def collect(cls, block_structure):
        """
        Collects data for each registered transformer.
        """
        for transformer in TransformerRegistry.get_registered_transformers():
            block_structure._add_transformer(transformer)  # pylint: disable=protected-access
            transformer.collect(block_structure)

        # Collect all fields that were requested by the transformers.
        block_structure._collect_requested_xblock_fields()  # pylint: disable=protected-access

    def transform(self, block_structure):
        """
        The given block structure is transformed by each transformer in the
        collection, in the order that the transformers were added.
        """
        optimized_transformers = []
        t_handlers = []
        complex_transformers = []
        for transformer in self._transformers:
            if transformer.TRANSFORM_TYPE == 'simple_remove':
                params = transformer.optimized_transform_prep(self.usage_info, block_structure)
                t_handlers.extend(transformer.optimized_transform_lambda(self.usage_info, block_structure, **params))
            else:
                complex_transformers.append(transformer)

        def filter_func(block_key):
            for t_handler in t_handlers:
                if 'filter' in t_handler and t_handler['filter'](block_key):
                    block_structure.remove_block(block_key, keep_descendants=t_handler.get('keep_descendants', False))
                    return False
            return True

        for _ in block_structure.topological_traversal(filter_func=filter_func):
            pass

        for transformer in complex_transformers:
            transformer.transform(self.usage_info, block_structure)

        # Prune the block structure to remove any unreachable blocks.
        block_structure._prune_unreachable()  # pylint: disable=protected-access

    @classmethod
    def is_collected_outdated(cls, block_structure):
        """
        Returns whether the collected data in the block structure is outdated.
        """
        outdated_transformers = []
        for transformer in TransformerRegistry.get_registered_transformers():
            version_in_block_structure = block_structure._get_transformer_data_version(transformer)  # pylint: disable=protected-access
            if transformer.VERSION != version_in_block_structure:
                outdated_transformers.append(transformer)

        if outdated_transformers:
            logger.info(
                "Collected Block Structure data for the following transformers is outdated: '%s'.",
                [(transformer.name(), transformer.VERSION) for transformer in outdated_transformers],
            )

        return bool(outdated_transformers)
