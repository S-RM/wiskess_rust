"""
Field Mapping - canonical field names and OpenSearch mapping for wiskess timelines

This centralizes the field-level knowledge needed to make the JSON produced by
polars_tln.py play nicely with OpenSearch: aliasing duplicate column names that
different tools use for the same concept, casting artefact-specific columns to
a consistent type, tagging rows with their source artefact, and the explicit
OpenSearch index mapping those choices imply.
"""

import json

import polars as pl

# Raw column name -> canonical name, for columns that different tools emit for
# the exact same concept. Only touches columns already explicitly whitelisted
# per-artefact via dict_tln[...]['msg'] in polars_tln.py, so a generic key
# like 'Name' can't accidentally catch an unrelated column from some other
# artefact.
FIELD_ALIASES = {
    'EventID': 'event_id',            # hayabusa
    'EventId': 'event_id',            # event-logs (EvtxECmd)
    'UserName': 'user_name',          # event-logs, srum_net_usages, srum_app_resusages
    'Username': 'user_name',          # shellbags
    'Name': 'file_name',              # usnjrnl-j (MFTECmd), matches rusty_usnjrnl
    'UpdateReasons': 'reason',        # usnjrnl-j (MFTECmd), matches rusty_usnjrnl
    'FileAttributes': 'file_attributes',  # usnjrnl-j (MFTECmd), matches rusty_usnjrnl
}

# Output column names df_time() always produces, regardless of artefact.
RESERVED_COLUMNS = ['message', 'timestamp_desc', 'hostname', 'doc_type']

# Canonical fields introduced by FIELD_ALIASES, mapped as text+keyword below.
_ALIAS_TARGET_FIELDS = sorted(set(FIELD_ALIASES.values()))

# The fields the user proposed, kept as given (text+keyword multi-field for
# everything except datetime and timesketch_label).
_PROPOSED_FIELDS = [
    'application', 'data', 'doc_type', 'event_type', 'exit_status', 'facility',
    'file_reference', 'file_size', 'flags', 'identifier', 'message_status',
    'message_type', 'offset', 'sequence_number', 'severity', 'source_port',
    'user_identifier', 'version', 'http_response_bytes',
]

_CORE_TEXT_KEYWORD_FIELDS = ['timestamp_desc', 'hostname'] + _PROPOSED_FIELDS + _ALIAS_TARGET_FIELDS


def _text_keyword_field():
    return {'type': 'text', 'fields': {'keyword': {'type': 'keyword', 'ignore_above': 1024}}}


def _build_mapping():
    properties = {name: _text_keyword_field() for name in sorted(set(_CORE_TEXT_KEYWORD_FIELDS))}
    properties['timesketch_label'] = {'type': 'nested'}
    properties['datetime'] = {'type': 'date'}
    properties['timestamp'] = {'type': 'date', 'format': 'epoch_millis'}
    properties['message'] = {'type': 'text'}

    return {
        'properties': properties,
        'dynamic_templates': [
            {
                'default_to_text_keyword': {
                    'match': '*',
                    'mapping': {
                        'type': 'text',
                        'fields': {'keyword': {'type': 'keyword', 'ignore_above': 1024}},
                    },
                }
            }
        ],
    }


OPENSEARCH_MAPPING = _build_mapping()


def apply(df, art, art_msg):
    """
    Normalize known duplicate/case-variant column names in art_msg to their
    canonical form, and build the polars select expressions needed for
    consistent, OpenSearch-friendly output.

    Returns (df, art_msg, msg_exprs, doc_type_expr):
      - df: the input frame, with any aliased columns renamed
      - art_msg: the column list, updated to canonical names
      - msg_exprs: a polars expression selecting art_msg cast to string
      - doc_type_expr: a polars expression aliasing the literal `art` value to 'doc_type'
    """
    renames = {
        col: FIELD_ALIASES[col]
        for col in art_msg
        if col in FIELD_ALIASES and FIELD_ALIASES[col] != col
    }
    if renames:
        df = df.rename(renames)
        art_msg = [FIELD_ALIASES.get(col, col) for col in art_msg]

    msg_exprs = pl.col(art_msg).cast(pl.Utf8, strict=False)
    doc_type_expr = pl.lit(art).alias('doc_type')
    return df, art_msg, msg_exprs, doc_type_expr


def write_mapping_file(path):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(OPENSEARCH_MAPPING, f, indent=2)
        f.write('\n')


if __name__ == '__main__':
    import os
    out_path = os.path.join(os.path.dirname(__file__), 'opensearch_mapping.json')
    write_mapping_file(out_path)
    print(f'Wrote {out_path}')
