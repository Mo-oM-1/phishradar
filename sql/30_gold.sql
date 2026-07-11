-- =============================================================================
-- PhishRadar - 30 : Couche GOLD (référentiel marques + scoring des alertes)
-- Cœur métier : Dynamic Table qui croise chaque domaine avec chaque marque
-- et calcule un score de menace (typosquatting / combosquatting / homoglyphes).
-- =============================================================================
USE ROLE PR_ENGINEER;
USE DATABASE PHISHRADAR;
USE SCHEMA GOLD;
USE WAREHOUSE WH_INGEST;

-- --- Référentiel des marques protégées (miroir de config/brands.yml) --------
CREATE OR REPLACE TABLE BRANDS (
  BRAND_NAME    STRING,
  BRAND_TOKEN   STRING,   -- forme compacte pour le matching : bnpparibas
  LEGIT_DOMAINS ARRAY     -- whitelist : jamais d'alerte sur ces domaines
);

-- Note : les littéraux ARRAY ne sont pas acceptés dans une clause VALUES,
-- d'où l'INSERT ... SELECT ... UNION ALL (ARRAY_CONSTRUCT par ligne).
INSERT INTO BRANDS (BRAND_NAME, BRAND_TOKEN, LEGIT_DOMAINS)
  SELECT 'BNP Paribas',       'bnpparibas',      ARRAY_CONSTRUCT('bnpparibas.com','bnpparibas.fr','bnpparibas.net','mabanque.bnpparibas')
  UNION ALL SELECT 'Crédit Agricole',   'creditagricole',  ARRAY_CONSTRUCT('credit-agricole.fr','credit-agricole.com')
  UNION ALL SELECT 'Société Générale',  'societegenerale', ARRAY_CONSTRUCT('societegenerale.fr','societegenerale.com','sg.fr')
  UNION ALL SELECT 'Crédit Mutuel',     'creditmutuel',    ARRAY_CONSTRUCT('creditmutuel.fr','creditmutuel.com','cmut.fr')
  UNION ALL SELECT 'La Banque Postale', 'banquepostale',   ARRAY_CONSTRUCT('labanquepostale.fr','labanquepostale.com')
  UNION ALL SELECT 'Caisse d''Épargne', 'caisseepargne',   ARRAY_CONSTRUCT('caisse-epargne.fr')
  UNION ALL SELECT 'Banque Populaire',  'banquepopulaire', ARRAY_CONSTRUCT('banquepopulaire.fr')
  UNION ALL SELECT 'BoursoBank',        'boursobank',      ARRAY_CONSTRUCT('boursobank.com','boursorama.com')
  UNION ALL SELECT 'Hello bank!',       'hellobank',       ARRAY_CONSTRUCT('hellobank.fr')
  UNION ALL SELECT 'PayPal',            'paypal',          ARRAY_CONSTRUCT('paypal.com','paypal.fr');

-- Termes de combosquatting (marque + mot rassurant)
CREATE OR REPLACE TABLE COMBO_TERMS (TERM STRING);
INSERT INTO COMBO_TERMS VALUES
  ('secure'),('security'),('securite'),('login'),('connexion'),('verify'),
  ('verification'),('compte'),('account'),('espace-client'),('espaceclient'),
  ('support'),('auth'),('banque'),('update'),('confirm');

-- --- Dynamic Table : les alertes scorées ------------------------------------
-- Rafraîchie automatiquement (TARGET_LAG) dès que SILVER.DOMAINS bouge.
CREATE OR REPLACE DYNAMIC TABLE ALERTS
  TARGET_LAG = '5 minutes'
  WAREHOUSE = WH_INGEST
AS
WITH scored AS (
  SELECT
    d.DOMAIN,
    d.REGISTERED_SLD,
    d.SLD_NORM,
    d.TLD,
    d.ISSUER,
    d.SEEN_AT,
    d.NOT_BEFORE,
    d.CERT_SHA256,
    b.BRAND_NAME,
    b.BRAND_TOKEN,
    EDITDISTANCE(d.SLD_NORM, b.BRAND_TOKEN)            AS edit_dist,
    JAROWINKLER_SIMILARITY(d.SLD_NORM, b.BRAND_TOKEN)  AS jw_sim,
    CONTAINS(REPLACE(d.DOMAIN, '-', ''), b.BRAND_TOKEN) AS contains_brand,
    EXISTS (SELECT 1 FROM COMBO_TERMS t WHERE CONTAINS(d.DOMAIN, t.TERM)) AS has_combo_term,
    -- whitelist : le domaine (ou son parent) est un domaine légitime
    EXISTS (
      SELECT 1 FROM TABLE(FLATTEN(b.LEGIT_DOMAINS)) l
      WHERE d.DOMAIN = l.VALUE::STRING OR ENDSWITH(d.DOMAIN, '.' || l.VALUE::STRING)
    ) AS is_legit
  FROM PHISHRADAR.SILVER.DOMAINS d
  CROSS JOIN BRANDS b
),
-- niveau intermédiaire : on matérialise ATTACK_TYPE et THREAT_SCORE
-- (Snowflake interdit de réutiliser un alias dans le même SELECT)
enriched AS (
  SELECT
    DOMAIN, BRAND_NAME, CERT_SHA256, ISSUER, SEEN_AT, NOT_BEFORE, TLD,
    edit_dist, jw_sim, is_legit, contains_brand,
    CASE
      WHEN contains_brand AND has_combo_term THEN 'COMBOSQUATTING'
      WHEN contains_brand                    THEN 'BRAND_ABUSE'
      WHEN edit_dist BETWEEN 1 AND 2         THEN 'TYPOSQUATTING'
      WHEN SLD_NORM <> REGISTERED_SLD AND edit_dist = 0 THEN 'HOMOGLYPH'
      ELSE 'FUZZY_MATCH'
    END AS ATTACK_TYPE,
    -- score 0-100 : pondération simple et lisible (expliquée dans le spec)
    LEAST(100,
        IFF(contains_brand, 50, 0)
      + IFF(has_combo_term, 25, 0)
      + IFF(edit_dist BETWEEN 1 AND 2, 60 - 15 * edit_dist, 0)
      + IFF(SLD_NORM <> REGISTERED_SLD AND edit_dist <= 1, 30, 0)
      + IFF(jw_sim >= 90, 15, 0)
    ) AS THREAT_SCORE
  FROM scored
)
SELECT
  DOMAIN, BRAND_NAME, CERT_SHA256, ISSUER, SEEN_AT, NOT_BEFORE, TLD,
  edit_dist, jw_sim, ATTACK_TYPE, THREAT_SCORE,
  CASE
    WHEN THREAT_SCORE >= 85 THEN 'CRITICAL'
    WHEN THREAT_SCORE >= 70 THEN 'HIGH'
    ELSE 'MEDIUM'
  END AS SEVERITY,
  CURRENT_TIMESTAMP() AS SCORED_AT
FROM enriched
WHERE NOT is_legit
  AND (contains_brand OR edit_dist <= 2 OR jw_sim >= 90)
  AND THREAT_SCORE >= 60;   -- seuil d'alerte (brands.yml : alert_score_min)
                            -- (WHERE et non QUALIFY : THREAT_SCORE vient du CTE, pas d'une fonction fenêtre)

-- --- Vue analyste : file de triage ------------------------------------------
CREATE OR REPLACE VIEW V_TRIAGE AS
SELECT SEVERITY, ATTACK_TYPE, DOMAIN, BRAND_NAME, THREAT_SCORE, ISSUER, SEEN_AT
FROM ALERTS
QUALIFY ROW_NUMBER() OVER (PARTITION BY DOMAIN, BRAND_NAME ORDER BY SEEN_AT DESC) = 1
ORDER BY THREAT_SCORE DESC, SEEN_AT DESC;
