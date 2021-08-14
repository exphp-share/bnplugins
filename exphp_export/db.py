import re
from binaryninja import log
import binaryninja as bn

from touhouReverseBnutil import recording_undo

class Metadata:
    BV_METADATA_KEY = 'exphp:db-datasync'

    def __init__(self, exe_version, last_sync_index):
        self.exe_version = exe_version
        # How long was the change list the last time we successfully performed a sync?
        self.last_sync_index = last_sync_index

    @classmethod
    def from_dict(cls, d):
        return cls(
            exe_version=d['exe-version'],
            last_sync_index=d['last-sync-index'],
        )
    def to_dict(self):
        return {
            'exe-version': self.exe_version,
            'last-sync-index': self.last_sync_index,
        }

    @classmethod
    def from_bv(cls, bv):
        try:
            d = bv.query_metadata(cls.BV_METADATA_KEY)
        except KeyError:
            raise RuntimeError('init_metadata has not been called on this BV')
        return cls.from_dict(d)

    @classmethod
    def initialize(cls, bv, exe_version):
        meta = cls(
            exe_version=exe_version,
            last_sync_index=0,
        )
        bv.store_metadata(cls.BV_METADATA_KEY, meta.to_dict())

    def store(self, bv):
        bv.store_metadata(self.BV_METADATA_KEY, self.to_dict())

class BinaryViewChanger:
    """ Type responsible for implementing syncable changes on an individual BinaryView.

    Methods generally resemble the methods on ChangesDb, but do not perform syncing
    and will not handle the bv's undo history.  They return True on success, False if
    the change does not appear applicable to this BinaryView, and they will raise an
    exception in cases that require human intervention.
    """
    def __init__(self, bv):
        self.bv = bv

    def _has_type(self, name):
        typ = self.bv.get_type_by_name(name)
        return typ is not None

    def rename_type(self, old, new, clobber_ok=False):
        """ Rename a type, returning True if it existed.

        Throws an exception if another type would be clobbered. """
        if self._has_type(old):
            if self._has_type(new) and not clobber_ok:
                raise RuntimeError(f'cannot rename {old} to {new}: destination exists')
            self.bv.rename_type(old, new)
            assert self._has_type(new)
            return True
        return False

    def rename_member(self, type_name, old, new):
        """ Rename a member of a type, returning True if it existed. """
        ty = self.bv.get_type_by_name(type_name)
        if ty is None:
            return False

        if ty.type_class == bn.TypeClass.StructureTypeClass:
            structure = ty.structure.mutable_copy()
            i = self._get_named_member_index(structure, old)
            if i is None:
                return False
            structure.replace(i, structure.members[i].type, new)
            new_ty = bn.Type.structure_type(structure)
        elif ty.type_class == bn.TypeClass.EnumerationTypeClass:
            enumeration = ty.enumeration.mutable_copy()
            i = self._get_named_member_index(enumeration, old)
            if i is None:
                return False
            enumeration.replace(i, new, enumeration.members[i].value)
            new_ty = bn.Type.enumeration_type(self.bv.arch, enumeration, width=ty.width, sign=ty.signed)
        else:
            return False

        self.bv.define_user_type(type_name, new_ty)
        return True

    def _get_named_member_index(self, structure_or_enumeration, name):
        member_names = [member.name for member in structure_or_enumeration.members]
        try:
            return member_names.index(name)
        except ValueError:
            return None

MUTATION_NAME_RE = re.compile(r'[a-zA-Z0-9_-]+')

class ChangesDb:
    """
    Client for the change database, to assist in syncing changes between multiple BinaryViews
    and the export data.

    User interface for the change DB, intended to be used directly from the REPL in binaryninja.
    """
    def __init__(self, url=f'http://localhost:4001/graphql'):
        from gql import Client
        from gql.transport.requests import RequestsHTTPTransport
        self.transport = RequestsHTTPTransport(url=url)
        self.client = Client(transport=self.transport, fetch_schema_from_transport=True)
        with self.client:  # test connectivity
            pass

    def sync(self, bv):
        from datetime import datetime

        with recording_undo(bv) as rec:
            changes = self._get_unsynced_changes(bv)
            for change_index, change in enumerate(changes, start=Metadata.from_bv(bv).last_sync_index):
                data = change['data']
                variant = data['__typename']
                if variant == 'CRenameType':
                    old, new = data['old'], data['new']
                    log_action = f'{old} -> {new}'
                    action = lambda: BinaryViewChanger(bv).rename_type(old, new)
                elif variant == 'CRenameMember':
                    tyname, old, new = data['type'], data['old'], data['new']
                    log_action = '{tyname}::({old} -> {new})'
                    action = lambda: BinaryViewChanger(bv).rename_member(tyname, old, new)
                else:
                    assert False, f'unknown change type: {change.__typename}'

                log_ts = datetime.fromtimestamp(change["timestamp"]).strftime("%m-%d %H:%M")
                log_source = f'(from {change["source"]})'
                full_message = lambda status: f'{change_index} [{log_ts}]: {status}: {log_source}: {log_action}'
                if change['active']:
                    try:
                        if action():
                            log.log_info(full_message('Applied'))
                            rec.enable_auto_rollback()
                        else:
                            log.log_info(full_message('Skipped'))
                    except:
                        log.log_error(full_message('Error'))
                        raise
                else:
                    log.log_info(full_message('Disabled'))

            meta = Metadata.from_bv(bv)
            meta.last_sync_index += len(changes)
            meta.store(bv)

    def rename_type(self, bv, old, new):
        def do_change(bv):
            if bv and not BinaryViewChanger(bv).rename_type(old, new):
                raise RuntimeError(f'type {old} is not present in bv')
        self._submit_change(bv, do_change, 'renameType', dict(old=old, new=new))

    def rename_member(self, bv, type, old, new):
        def do_change(bv):
            if bv and not BinaryViewChanger(bv).rename_member(type, old, new):
                raise RuntimeError(f'missing type or member in {type}::{old}')
        self._submit_change(bv, do_change, 'renameMember', dict(type=type, old=old, new=new))

    def _get_unsynced_changes(self, bv):
        from gql import gql

        with self.client as session:
            assert self.client.schema is not None
            meta = Metadata.from_bv(bv)
            query = gql("""
                query ($startIndex: Int!) {
                    changes(startIndex: $startIndex) {
                        timestamp
                        source
                        active
                        data {
                            __typename
                            ... on CRenameType { old new }
                            ... on CRenameMember { type old new }
                        }
                    }
                }
            """)
            result = session.execute(query, variable_values=dict(startIndex=meta.last_sync_index))
            return result['changes']

    def disable_change(self, index):
        from gql import gql

        with self.client as session:
            query = gql("""
                mutation ($index: Int!) {
                    disableChange(index: $index)
                }
            """)
            result = session.execute(query, variable_values=dict(index=index))
            return result['disableChange']

    def _submit_change(self, bv, do_change, mutation_name, additional_fields):
        from gql.dsl import DSLSchema, dsl_gql, DSLMutation

        with recording_undo(bv) as rec:
            # Optimistically perform the change to the local BinaryView.
            #
            # If submitting to the Sync DB fails, we'll get an exception
            # and the change will be rolled back.
            do_change(bv)
            rec.enable_auto_rollback()

            with self.client as session:
                assert self.client.schema is not None
                ds = DSLSchema(self.client.schema)
                meta = Metadata.from_bv(bv)
                query = dsl_gql(DSLMutation(
                    getattr(ds.Mutation, mutation_name)(**dict({
                        'as': f'bndb {meta.exe_version}',
                        'syncIndex': meta.last_sync_index,
                    }, **additional_fields))
                ))
                result = session.execute(query)
                pushed_index = result[mutation_name]

                # This operation is atomic, so the returned index should be predictable
                if pushed_index != meta.last_sync_index:
                    log.log_error(f'oddity in sync index after push ({meta.last_sync_index} != {pushed_index})')
                meta.last_sync_index += 1  # the new change is already synced!
                meta.store(bv)
                print(f'Stored at index {pushed_index}')


