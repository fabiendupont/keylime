"""Add spdm_cert_chain to registrar

Revision ID: b7d1e4c92a15
Revises: a59cc9366774
Create Date: 2026-11-17

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "b7d1e4c92a15"
down_revision = "a59cc9366774"
branch_labels = None
depends_on = None


def upgrade(engine_name):
    globals()[f"upgrade_{engine_name}"]()


def downgrade(engine_name):
    globals()[f"downgrade_{engine_name}"]()


def upgrade_registrar():
    with op.batch_alter_table("registrarmain") as batch_op:
        batch_op.add_column(sa.Column("spdm_cert_chain", sa.String(), nullable=True))


def downgrade_registrar():
    with op.batch_alter_table("registrarmain") as batch_op:
        batch_op.drop_column("spdm_cert_chain")


def upgrade_cloud_verifier():
    pass


def downgrade_cloud_verifier():
    pass
