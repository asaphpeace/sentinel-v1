"""report ingestion idempotency: unique (domain_id, report_id)

The IMAP poller (imap_service.poll_inbox) has no idempotency check before
inserting a DmarcReport/TlsReport — if the same message is ever processed
twice (overlapping poll runs, a message that errors after insert but before
being marked \\Seen and gets retried), the report's records are inserted a
second time, silently double-counting volume in DmarcAggregate/TlsAggregate.
That corrupts compliance %, the Sentinel Score, and every gate in the
recommendation engine, since they all trust total_count/pass_count being
accurate.

This is a partial unique index (WHERE report_id != '') rather than a flat
unique constraint, since some malformed reports omit report_id entirely —
we don't want two distinct reports with an empty id to be treated as
duplicates of each other.

Revision ID: a7b8c9d0e1f2
Revises: f6a7b8c9d0e1
Create Date: 2026-06-21
"""
from alembic import op

revision = 'a7b8c9d0e1f2'
down_revision = 'f6a7b8c9d0e1'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Dedupe existing rows first — this bug has already produced duplicate
    # report rows in at least one environment (verified before writing this
    # migration), and creating a unique index against data that violates it
    # would simply fail. Keep the earliest-received copy per (domain_id,
    # report_id) group; cascade-delete (ondelete=CASCADE on the child FKs)
    # takes care of the now-orphaned DmarcRecord/TlsPolicy/TlsFailureDetail
    # rows automatically. DmarcAggregate/TlsAggregate still need an explicit
    # rebuild after this — that's an application-level step, not something
    # this migration can do (it has no access to rebuild_aggregates()).
    op.execute("""
        DELETE FROM dmarc_reports a
        USING dmarc_reports b
        WHERE a.domain_id = b.domain_id
          AND a.report_id = b.report_id
          AND a.report_id != ''
          AND (a.received_at > b.received_at OR (a.received_at = b.received_at AND a.id > b.id))
    """)
    op.execute("""
        DELETE FROM tls_reports a
        USING tls_reports b
        WHERE a.domain_id = b.domain_id
          AND a.report_id = b.report_id
          AND a.report_id != ''
          AND (a.received_at > b.received_at OR (a.received_at = b.received_at AND a.id > b.id))
    """)

    op.execute(
        "CREATE UNIQUE INDEX uq_dmarc_reports_domain_report "
        "ON dmarc_reports (domain_id, report_id) WHERE report_id != ''"
    )
    op.execute(
        "CREATE UNIQUE INDEX uq_tls_reports_domain_report "
        "ON tls_reports (domain_id, report_id) WHERE report_id != ''"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS uq_dmarc_reports_domain_report")
    op.execute("DROP INDEX IF EXISTS uq_tls_reports_domain_report")
