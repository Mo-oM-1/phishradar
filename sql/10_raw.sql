-- =============================================================================
-- PhishRadar - 10 : Couche RAW (stage interne + COPY automatisé par TASK)
-- Le script Python fait PUT sur le stage ; la task charge toutes les minutes.
-- =============================================================================
USE ROLE PR_ENGINEER;
USE DATABASE PHISHRADAR;
USE SCHEMA RAW;
USE WAREHOUSE WH_INGEST;

CREATE FILE FORMAT IF NOT EXISTS FF_JSONL
  TYPE = JSON STRIP_OUTER_ARRAY = FALSE COMPRESSION = GZIP;

CREATE STAGE IF NOT EXISTS CERT_STAGE
  FILE_FORMAT = FF_JSONL
  COMMENT = 'Dépôt des batches JSONL gzip envoyés par certstream_ingest.py';

-- Table RAW : le message certstream complet en VARIANT, sans transformation.
CREATE TABLE IF NOT EXISTS CERTS (
  V          VARIANT,
  FILE_NAME  STRING,
  LOADED_AT  TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

-- Chargement automatisé : COPY toutes les minutes, purge des fichiers chargés.
-- (Alternative "premium" : Snowpipe Streaming SDK pour du ligne-à-ligne.)
CREATE OR REPLACE TASK T_LOAD_CERTS
  WAREHOUSE = WH_INGEST
  SCHEDULE = '1 MINUTE'
AS
  COPY INTO CERTS (V, FILE_NAME)
  FROM (SELECT $1, METADATA$FILENAME FROM @CERT_STAGE)
  PURGE = TRUE
  ON_ERROR = 'CONTINUE';

ALTER TASK T_LOAD_CERTS RESUME;

-- Stream : alimente la couche SILVER en ne traitant que les nouveautés (CDC).
CREATE STREAM IF NOT EXISTS CERTS_STRM ON TABLE CERTS;
