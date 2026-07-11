-- =============================================================================
-- PhishRadar - 05 : Intégration Git native (repo GitHub monté dans Snowflake)
-- Le repo devient un "stage" : on liste les fichiers, on exécute les scripts
-- directement depuis GitHub. Repo public -> aucun secret nécessaire.
-- Prérequis : 00_setup.sql. Remplace <TON_USER> par ton username GitHub.
-- =============================================================================
USE ROLE ACCOUNTADMIN;

-- 1. Intégration API vers GitHub (autorise le préfixe de ton compte)
CREATE OR REPLACE API INTEGRATION GITHUB_INTEGRATION
  API_PROVIDER = GIT_HTTPS_API
  API_ALLOWED_PREFIXES = ('https://github.com/<TON_USER>')
  ENABLED = TRUE;

-- 2. Le repo monté comme objet Snowflake
CREATE OR REPLACE GIT REPOSITORY PHISHRADAR.RAW.PHISHRADAR_REPO
  API_INTEGRATION = GITHUB_INTEGRATION
  ORIGIN = 'https://github.com/<TON_USER>/phishradar.git';

GRANT USAGE ON GIT REPOSITORY PHISHRADAR.RAW.PHISHRADAR_REPO TO ROLE PR_ENGINEER;

-- 3. Synchroniser (à relancer après chaque push : c'est un FETCH, pas un webhook)
ALTER GIT REPOSITORY PHISHRADAR.RAW.PHISHRADAR_REPO FETCH;

-- 4. Vérifier : lister les fichiers du repo vus depuis Snowflake
LS @PHISHRADAR.RAW.PHISHRADAR_REPO/branches/main/sql/;

-- 5. Exécuter les scripts directement depuis GitHub (déploiement reproductible)
-- EXECUTE IMMEDIATE FROM @PHISHRADAR.RAW.PHISHRADAR_REPO/branches/main/sql/10_raw.sql;
-- EXECUTE IMMEDIATE FROM @PHISHRADAR.RAW.PHISHRADAR_REPO/branches/main/sql/20_silver.sql;
-- EXECUTE IMMEDIATE FROM @PHISHRADAR.RAW.PHISHRADAR_REPO/branches/main/sql/30_gold.sql;
