#!/usr/bin/env python3
"""Schema-only checks; this does not execute or typecheck native Rust restoration."""
import copy
import hashlib
import json
import pathlib
import re

from jsonschema import Draft202012Validator

ROOT = pathlib.Path(__file__).resolve().parents[1]
PATHS = {
    'report': ROOT / 'schemas/archive_export_restoration.v1.json',
    'completion': ROOT / 'schemas/archive_restore_completion.v1.json',
}
SCHEMAS = {key: json.loads(path.read_text()) for key, path in PATHS.items()}
for schema in SCHEMAS.values():
    Draft202012Validator.check_schema(schema)
VALIDATORS = {key: Draft202012Validator(schema) for key, schema in SCHEMAS.items()}

def digest(value):
    return 'sha256:' + hashlib.sha256(value.encode()).hexdigest()

context = {
    'codec': 'hevc', 'sensor': 'sensor:restoration-fixture',
    'stream': 'stream:restoration-fixture', 'generation': 1,
    'anchor': digest('anchor'), 'receive_clock': digest('receive'),
    'decode_clock': digest('decode'), 'time_scale': 90000,
    'namespace': digest('namespace'), 'completion_sha256': digest('original-completion'),
    'request_sha256_observed': digest('request'),
    'request_binding': 'semantic_consistency_only_unpinned_by_completion_v1',
    'original_snapshot_claim': digest('original-snapshot'),
    'original_query': [0, 172000],
}
claims = {
    'native_source_provenance_verified': True, 'playback_bytes_verified': True,
    'decoded_pictures_verified': False, 'original_catalog_reconstructed': False,
    'original_clock_index_restored': False, 'coverage_claim': 'not_claimed',
    'filesystem_snapshot_atomic': False,
}
success = {
    'schema': 'fss.local_archive_export_restoration.v1', 'command': 'restore-export',
    **context, 'phase': 'complete', 'output_created': True,
    'source_preflight_verified': True, 'selected_windows': 2,
    'restored_windows': 2, 'restored_pages': 1, 'indexed_windows': 2,
    'pending_window': False, 'pending_page': False, 'new_snapshot': digest('new-snapshot'),
    'destination_cold_verified': True, 'restore_completion_sha256': digest('restore-completion'),
    'restore_completion_visible': True, 'restore_completion_durable': True,
    'input_read_bytes_charged': 100000, 'input_io_calls_charged': 5000,
    'input_accounting': 'observed_reads', 'local_io_bytes_charged': 500000,
    'local_io_operations_charged': 20000, 'writer_steps': 11,
    **claims, 'publication_reconciliation_required': False, 'complete': True,
}
receipt = {
    'schema': 'fss.local_archive_restore_completion.v1', **context,
    'new_snapshot': digest('new-snapshot'), 'restored_windows': 2,
    'restored_pages': 1, 'indexed_windows': 2, 'retained_objects': 11,
    'retained_bytes': 25000, **claims, 'complete': True,
}

positive = []
negative = []

def accepts(kind, label, value):
    errors = list(VALIDATORS[kind].iter_errors(value))
    assert not errors, (kind, label, [e.message for e in errors])
    positive.append((kind, label))

def refuses(kind, label, value):
    errors = list(VALIDATORS[kind].iter_errors(value))
    assert errors, (kind, label, 'contradiction was accepted')
    negative.append((kind, label))

def changed(base, **updates):
    result = copy.deepcopy(base)
    result.update(updates)
    return result

def partial(phase, **updates):
    return changed(success, **{
        'phase': phase, 'complete': False, 'publication_reconciliation_required': True,
        'new_snapshot': None, 'destination_cold_verified': False,
        'restore_completion_sha256': None, 'restore_completion_visible': False,
        'restore_completion_durable': False, **updates,
    })

for codec in ['avc', 'hevc']:
    accepts('report', codec + '-complete', changed(success, codec=codec))
    accepts('completion', codec + '-completion', changed(receipt, codec=codec))
    accepts('report', codec + '-empty', changed(
        success, codec=codec, selected_windows=0, restored_windows=0,
        indexed_windows=0, restored_pages=0, writer_steps=1))
    accepts('completion', codec + '-empty-completion', changed(
        receipt, codec=codec, restored_windows=0, indexed_windows=0,
        restored_pages=0, retained_objects=0, retained_bytes=0))
    accepts('report', codec + '-maximum-scoped-counters', changed(
        success, codec=codec, generation=2**64-1, time_scale=2**32-1,
        original_query=[2**64-2, 2**64-1], selected_windows=4096,
        restored_windows=4096, indexed_windows=4096, restored_pages=64,
        input_read_bytes_charged=2**40, input_io_calls_charged=4000000,
        local_io_bytes_charged=2**40, local_io_operations_charged=16000000,
        writer_steps=49168, sensor='.'*128, stream='_'*128))
    accepts('completion', codec + '-maximum-scoped-completion', changed(
        receipt, codec=codec, generation=2**64-1, time_scale=2**32-1,
        original_query=[2**64-2, 2**64-1], restored_windows=4096,
        indexed_windows=4096, restored_pages=64, retained_objects=131072,
        retained_bytes=2**40))

opening = partial('opening_destination', restored_windows=0, restored_pages=0,
                  indexed_windows=0, writer_steps=0, local_io_bytes_charged=0,
                  local_io_operations_charged=1)
accepts('report', 'created-but-owner-open-refused', opening)
accepts('report', 'empty-selection-owner-open-refused', changed(opening, selected_windows=0))
for pending in [False, True]:
    accepts('report', 'first-window-pending-' + str(pending), partial(
        'restoring_windows', restored_windows=0, restored_pages=0, indexed_windows=0,
        pending_window=pending, input_accounting='remaining_reservation_retained'))
accepts('report', 'durable-private-window-unindexed', partial(
    'restoring_windows', restored_windows=1, restored_pages=0, indexed_windows=0,
    input_accounting='remaining_reservation_retained'))
accepts('report', 'private-prefix-page-next-window-pending', partial(
    'restoring_windows', selected_windows=65, restored_windows=64, restored_pages=1,
    indexed_windows=64, pending_window=True, input_accounting='remaining_reservation_retained'))
for accounting in ['observed_reads', 'remaining_reservation_retained']:
    accepts('report', 'second-pass-finish-' + accounting, partial(
        'checking_source_again', restored_pages=0, indexed_windows=0,
        input_accounting=accounting))
accepts('report', 'catalog-prepared-not-acknowledged', partial(
    'publishing_catalogs', restored_pages=0, indexed_windows=0, pending_page=True))
accepts('report', 'catalog-acknowledged-writer-not-finished', partial('publishing_catalogs'))
accepts('report', 'writer-finished-poststep-refusal', partial(
    'publishing_catalogs', new_snapshot=digest('new-snapshot')))
accepts('report', 'cold-reopen-refused', partial(
    'reopening_archive', new_snapshot=digest('new-snapshot')))
accepts('report', 'cold-reopen-verified-postcheck-refused', partial(
    'reopening_archive', new_snapshot=digest('new-snapshot'), destination_cold_verified=True))
accepts('report', 'completion-not-yet-prepared', partial(
    'publishing_completion', new_snapshot=digest('new-snapshot'), destination_cold_verified=True))
for visible, durable in [(False, False), (True, False), (True, True)]:
    value = partial('publishing_completion', new_snapshot=digest('new-snapshot'),
                    destination_cold_verified=True, restore_completion_sha256=digest('restore-completion'),
                    restore_completion_visible=visible, restore_completion_durable=durable)
    accepts('report', f'completion-visible-{visible}-durable-{durable}-still-incomplete', value)
late = partial('publishing_completion', new_snapshot=digest('new-snapshot'),
               destination_cold_verified=True, restore_completion_sha256=digest('restore-completion'),
               restore_completion_visible=True, restore_completion_durable=True)
accepts('report', 'late-cancellation-of-empty-selection', changed(
    late, selected_windows=0, restored_windows=0, indexed_windows=0, restored_pages=0))

for kind, base in [('report', success), ('completion', receipt)]:
    accepts(kind, 'exact-v2-request-binding', changed(base, request_binding='sha256_pinned_by_completion_v2'))
    for name in SCHEMAS[kind]['required']:
        bad = copy.deepcopy(base)
        del bad[name]
        refuses(kind, 'missing-' + name, bad)
    refuses(kind, 'unknown-key', changed(base, unexpected=True))
    for name, value in [
        ('schema', 'fss.unknown.v1'), ('codec', 'auto'), ('sensor', 'private/path'),
        ('stream', ''), ('sensor', 'a'*129), ('generation', 0), ('generation', 2**64),
        ('time_scale', 0), ('time_scale', 2**32), ('anchor', 'sha256:'+'A'*64),
        ('receive_clock', None), ('completion_sha256', digest('x')+'0'),
        ('original_query', [0, 0]), ('original_query', [1]),
        ('original_query', [0, 1, 2]), ('original_query', [2**64, 2**64+1]),
        ('original_query', [0, 1.5]), ('request_binding', 'independently_pinned'),
        ('restored_windows', 4097), ('restored_pages', 4097), ('indexed_windows', 4097),
        ('native_source_provenance_verified', False), ('playback_bytes_verified', False),
        ('decoded_pictures_verified', True), ('original_catalog_reconstructed', True),
        ('original_clock_index_restored', True), ('coverage_claim', 'absence_proven'),
        ('filesystem_snapshot_atomic', True),
    ]:
        refuses(kind, f'bad-{name}-{value}', changed(base, **{name:value}))

for name, value in [
    ('command', 'verify-export'), ('phase', 'restoring_windows'), ('output_created', False),
    ('source_preflight_verified', False), ('pending_window', True), ('pending_page', True),
    ('new_snapshot', None), ('destination_cold_verified', False),
    ('restore_completion_sha256', None), ('restore_completion_visible', False),
    ('restore_completion_durable', False), ('input_accounting', 'remaining_reservation_retained'),
    ('publication_reconciliation_required', True), ('writer_steps', 0), ('writer_steps', 49169),
    ('input_read_bytes_charged', 2**40+1), ('input_io_calls_charged', 4000001),
    ('local_io_bytes_charged', 2**40+1), ('local_io_operations_charged', 16000001),
    ('local_io_operations_charged', 0), ('selected_windows', 0), ('restored_windows', 0),
    ('indexed_windows', 0), ('restored_pages', 0), ('complete', False),
]:
    refuses('report', f'inconsistent-complete-{name}', changed(success, **{name:value}))
for name, value in [
    ('restore_completion_visible', False), ('restore_completion_sha256', None),
    ('destination_cold_verified', False), ('pending_page', True), ('pending_window', True),
    ('publication_reconciliation_required', False), ('input_accounting', 'remaining_reservation_retained'),
    ('phase', 'opening_destination'),
]:
    refuses('report', f'inconsistent-late-cancellation-{name}', changed(late, **{name:value}))
for name, value in [('complete', False), ('new_snapshot', None), ('restored_windows', 0),
                    ('indexed_windows', 0), ('restored_pages', 0), ('retained_objects', 0),
                    ('retained_bytes', 0), ('retained_bytes', 2**40+1), ('retained_objects', 131073)]:
    refuses('completion', f'inconsistent-completion-{name}', changed(receipt, **{name:value}))

# Check schema names against every field emitted by the current native format strings.
# This is structural source inspection, not execution of those Rust format strings.
source = (ROOT / 'crates/fss-cli/src/archive_cmd/restore_export.rs').read_text()
context_source = source.split('fn context(', 1)[1].split('fn completion_report(', 1)[0]
completion_source = source.split('fn completion_report(', 1)[1].split('fn report(', 1)[0]
report_source = source.split('fn report(', 1)[1].split('fn bounded(', 1)[0]
keys = lambda text: set(re.findall(r'\\"([a-z0-9_]+)\\":', text))
for kind, body in [('report', report_source), ('completion', completion_source)]:
    native = keys(context_source) | keys(body)
    assert native == set(SCHEMAS[kind]['properties']), (kind, native ^ set(SCHEMAS[kind]['properties']))

result = {
    'schemas_checked': len(SCHEMAS), 'coherent_states_accepted': len(positive),
    'contradictions_rejected': len(negative),
    'emitted_field_sets_match': {key:len(schema['properties']) for key,schema in SCHEMAS.items()},
    'late_cancellation_after_durable_completion_accepted': True,
    'native_rust_execution': False,
    'cross_field_numeric_equality_is_native_obligation': True,
}
print(json.dumps(result, indent=2))
