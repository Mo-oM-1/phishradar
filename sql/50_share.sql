-- =============================================================================
-- PhishRadar - 50 : Secure Data Share (diffusion des IOC à un partenaire)
-- Cas d'usage réel : les équipes cyber partagent leurs indicateurs de
-- compromission (IOC) entre organisations. Ici via un share + reader account.
-- =============================================================================
USE ROLE ACCOUNTADMIN;

CREATE SHARE IF NOT EXISTS PHISHRADAR_IOC_SHARE
  COMMENT = 'Feed IOC PhishRadar - domaines de phishing détectés (TLP:AMBER)';

GRANT USAGE ON DATABASE PHISHRADAR                 TO SHARE PHISHRADAR_IOC_SHARE;
GRANT USAGE ON SCHEMA PHISHRADAR.GOLD              TO SHARE PHISHRADAR_IOC_SHARE;
GRANT SELECT ON VIEW PHISHRADAR.GOLD.V_IOC_FEED    TO SHARE PHISHRADAR_IOC_SHARE;

-- Reader account : simule le partenaire sans second compte Snowflake payant.
-- (Idéal pour la démo : tu te connectes au reader account et tu montres que
--  seules les colonnes/lignes autorisées sont visibles.)
CREATE MANAGED ACCOUNT IF NOT EXISTS PARTNER_SOC
  ADMIN_NAME = 'partner_admin'
  ADMIN_PASSWORD = '<CHANGE_ME_Str0ng!>'
  TYPE = READER;

-- Récupérer le locator du reader account puis :
-- ALTER SHARE PHISHRADAR_IOC_SHARE ADD ACCOUNTS = <locator>;
SHOW MANAGED ACCOUNTS;

-- --- Bonus certif : Time Travel & Zero-Copy Clone ----------------------------
-- Environnement de test instantané, sans dupliquer le stockage :
-- CREATE DATABASE PHISHRADAR_DEV CLONE PHISHRADAR;
-- Restauration après fausse manip :
-- SELECT * FROM PHISHRADAR.GOLD.ALERTS AT(OFFSET => -3600);
