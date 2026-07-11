-- =============================================================================
-- PhishRadar - 20 : Couche SILVER (normalisation des domaines)
-- FLATTEN du JSON, extraction du domaine enregistrable, normalisation
-- anti-homoglyphes/leetspeak, déduplication par empreinte de certificat.
-- =============================================================================
USE ROLE PR_ENGINEER;
USE DATABASE PHISHRADAR;
USE SCHEMA SILVER;
USE WAREHOUSE WH_INGEST;

CREATE TABLE IF NOT EXISTS DOMAINS (
  CERT_SHA256     STRING,
  DOMAIN          STRING,          -- ex : login-bnpparibas.evil.com
  REGISTERED_SLD  STRING,          -- label principal : evil / bnpparibas-secure
  TLD             STRING,          -- com / net / fr ...
  SLD_NORM        STRING,          -- dé-leetspeaké : paypa1 -> paypal
  IS_WILDCARD     BOOLEAN,
  ISSUER          STRING,
  NOT_BEFORE      TIMESTAMP_NTZ,
  NOT_AFTER       TIMESTAMP_NTZ,
  SEEN_AT         TIMESTAMP_NTZ,   -- data.seen du flux CT
  CT_LOG          STRING,
  LOADED_AT       TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
  CONSTRAINT PK_DOMAINS PRIMARY KEY (CERT_SHA256, DOMAIN) NOT ENFORCED
)
CLUSTER BY (TO_DATE(SEEN_AT));      -- volume élevé -> clustering par date

-- Task de transformation : consomme le stream RAW, une fois par minute,
-- uniquement s'il y a des données (zéro crédit consommé sinon).
CREATE OR REPLACE TASK T_TRANSFORM_CERTS
  WAREHOUSE = WH_INGEST
  SCHEDULE = '1 MINUTE'
  WHEN SYSTEM$STREAM_HAS_DATA('PHISHRADAR.RAW.CERTS_STRM')
AS
INSERT INTO DOMAINS
  (CERT_SHA256, DOMAIN, REGISTERED_SLD, TLD, SLD_NORM, IS_WILDCARD,
   ISSUER, NOT_BEFORE, NOT_AFTER, SEEN_AT, CT_LOG)
WITH exploded AS (
  SELECT
    s.V:data:leaf_cert:sha256::STRING            AS cert_sha256,
    LOWER(d.VALUE::STRING)                       AS raw_domain,
    s.V:data:leaf_cert:issuer:O::STRING          AS issuer,
    TO_TIMESTAMP_NTZ(s.V:data:leaf_cert:not_before::NUMBER) AS not_before,
    TO_TIMESTAMP_NTZ(s.V:data:leaf_cert:not_after::NUMBER)  AS not_after,
    TO_TIMESTAMP_NTZ(s.V:data:seen::NUMBER)      AS seen_at,
    s.V:data:source:name::STRING                 AS ct_log
  FROM PHISHRADAR.RAW.CERTS_STRM s,
       LATERAL FLATTEN(input => s.V:data:leaf_cert:all_domains) d
  WHERE s.METADATA$ACTION = 'INSERT'
),
parsed AS (
  SELECT
    cert_sha256,
    LTRIM(raw_domain, '*.')                                        AS domain,
    STARTSWITH(raw_domain, '*.')                                   AS is_wildcard,
    -- label enregistrable = avant-dernier label (approximation v1 ;
    -- les TLD composés type .co.uk sont traités dans la vue GOLD)
    SPLIT_PART(LTRIM(raw_domain, '*.'), '.', -2)                   AS registered_sld,
    SPLIT_PART(raw_domain, '.', -1)                                AS tld,
    issuer, not_before, not_after, seen_at, ct_log
  FROM exploded
)
SELECT
  cert_sha256,
  domain,
  registered_sld,
  tld,
  -- normalisation homoglyphes/leetspeak : 0->o 1->l 3->e 4->a 5->s 7->t 8->b, rn->m
  REPLACE(TRANSLATE(registered_sld, '0134578', 'oleastb'), 'rn', 'm') AS sld_norm,
  is_wildcard,
  issuer, not_before, not_after, seen_at, ct_log
FROM parsed
QUALIFY ROW_NUMBER() OVER (PARTITION BY cert_sha256, domain ORDER BY seen_at) = 1;

ALTER TASK T_TRANSFORM_CERTS RESUME;

-- Recherche fréquente par sous-chaîne de marque -> search optimization
ALTER TABLE DOMAINS ADD SEARCH OPTIMIZATION ON SUBSTRING(DOMAIN);
