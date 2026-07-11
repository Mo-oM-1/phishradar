-- =============================================================================
-- PhishRadar - 40 : Gouvernance (masking, row access, tags, secure view)
-- Domaine "Data Protection & Sharing" de la certif, natif au cas d'usage :
-- on partage des IOC à des partenaires SANS exposer nos détails internes.
-- =============================================================================
USE ROLE PR_ADMIN;
USE DATABASE PHISHRADAR;
USE SCHEMA GOV;

-- --- Classification par tags -------------------------------------------------
CREATE TAG IF NOT EXISTS TLP ALLOWED_VALUES 'CLEAR','GREEN','AMBER','RED'
  COMMENT = 'Traffic Light Protocol - standard de partage en threat intel';

ALTER TABLE PHISHRADAR.GOLD.ALERTS SET TAG GOV.TLP = 'AMBER';

-- --- Masking : l'empreinte du certificat est un détail interne ---------------
CREATE MASKING POLICY IF NOT EXISTS MASK_CERT_HASH AS (val STRING)
  RETURNS STRING ->
  CASE
    WHEN IS_ROLE_IN_SESSION('PR_ANALYST') THEN val
    ELSE '***MASKED***'
  END;

ALTER TABLE PHISHRADAR.GOLD.ALERTS
  MODIFY COLUMN CERT_SHA256 SET MASKING POLICY GOV.MASK_CERT_HASH;

-- --- Row access : un partenaire ne voit que les alertes CRITICAL/HIGH --------
CREATE ROW ACCESS POLICY IF NOT EXISTS RAP_PARTNER AS (severity STRING)
  RETURNS BOOLEAN ->
  IS_ROLE_IN_SESSION('PR_ANALYST')                -- interne : tout
  OR severity IN ('CRITICAL','HIGH');             -- partenaire : le confirmé

ALTER TABLE PHISHRADAR.GOLD.ALERTS ADD ROW ACCESS POLICY GOV.RAP_PARTNER ON (SEVERITY);

-- --- Secure view : le feed IOC exposé aux partenaires ------------------------
-- Colonnes minimales, définition non visible (SECURE), politiques appliquées.
CREATE OR REPLACE SECURE VIEW PHISHRADAR.GOLD.V_IOC_FEED AS
SELECT DOMAIN, BRAND_NAME, ATTACK_TYPE, THREAT_SCORE, SEVERITY, SEEN_AT
FROM PHISHRADAR.GOLD.ALERTS;

GRANT SELECT ON VIEW PHISHRADAR.GOLD.V_IOC_FEED TO ROLE PR_PARTNER;
