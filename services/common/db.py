import os

import psycopg
from psycopg.rows import dict_row


def connect() -> psycopg.Connection:
    # Lab: one connection per request. Production: a pool (psycopg_pool) and TLS to the DB.
    return psycopg.connect(os.environ["DATABASE_URL"], row_factory=dict_row, connect_timeout=5)
