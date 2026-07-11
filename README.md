# PhishRadar 🎯

**Détection en temps réel de domaines de phishing ciblant les banques françaises, via les Certificate Transparency logs, sur Snowflake.**

Chaque certificat HTTPS émis dans le monde est inscrit publiquement dans les CT logs. Les cybercriminels y enregistrent leurs faux domaines (`bnpparibas-secure.net`, `paypa1.com`) juste avant leurs campagnes. PhishRadar interroge ces journaux publics en continu, compare chaque nouveau domaine aux marques protégées (matching flou : distance d'édition, Jaro-Winkler, détection d'homoglyphes) et produit des alertes scorées, partagées de façon sécurisée à des partenaires.

**Zéro infrastructure à héberger** : le collecteur consomme directement l'API HTTP publique des CT logs (RFC 6962 : `get-sth` / `get-entries`) — pas de serveur, pas de Docker, pas de websocket. Un seul script Python.

## Architecture

```
CT logs publics (Google Argon/Xenon, Let's Encrypt, …)
        │  API HTTP RFC 6962 — polling ~20 s
        ▼
ct_poller.py : parsing X.509 + pré-filtre marques (~99,9 % écarté)
        │  PUT JSONL gzip
        ▼
┌─────────────────────── SNOWFLAKE ────────────────────────┐
│ @CERT_STAGE ─COPY(task 1 min)→ RAW.CERTS (VARIANT)       │
│      └─ STREAM ─→ task ─→ SILVER.DOMAINS (normalisés)    │
│                              └─→ GOLD.ALERTS             │
│                                  (Dynamic Table, scoring) │
│ Gouvernance : RBAC, masking, row access, tags TLP         │
│ Partage : SECURE VIEW → SHARE → reader account partenaire │
└───────────────────────────────────────────────────────────┘
```

## Démarrage rapide

```bash
# 1. Objets Snowflake (dans l'ordre, rôles indiqués en tête de chaque script)
#    sql/00_setup.sql → 01_rbac.sql → 10_raw.sql → 20_silver.sql
#    → 30_gold.sql → 40_governance.sql → 50_share.sql

# 2. Collecteur (rien d'autre à installer ni héberger) - géré avec uv
uv sync
export SNOWFLAKE_ACCOUNT=xxx SNOWFLAKE_USER=xxx SNOWFLAKE_PASSWORD=xxx
uv run ingest/ct_poller.py
```

Le collecteur découvre automatiquement les CT logs actifs via la liste officielle Chrome, mémorise sa position (`.ct_state.json`) et reprend où il s'était arrêté. Premières alertes dans `GOLD.V_TRIAGE` en quelques minutes.

## Maîtrise des coûts (trial 400 $)

Le pré-filtrage côté client écarte ~99,9 % du flux avant Snowflake. Warehouses XS avec auto-suspend 60 s, tasks conditionnées par `SYSTEM$STREAM_HAS_DATA` (zéro crédit si rien à traiter), resource monitor à 30 crédits/mois avec suspension automatique. En pratique : quelques crédits par semaine.

## Mapping certification SnowPro Core

| Domaine certif | Où dans le projet |
|---|---|
| Data Loading & Transformation | Stage interne, `COPY INTO`, `VARIANT` + `FLATTEN`, file formats |
| Data Pipelines | Streams (CDC), Tasks chaînées, Dynamic Tables (`TARGET_LAG`) |
| Security & Access Control | Hiérarchie de rôles SOC (`01_rbac.sql`), grants sur futurs objets |
| Data Protection & Sharing | Masking policy, row access policy, tags TLP, secure view, Secure Data Share, reader account, Time Travel, zero-copy clone |
| Performance | Clustering key, Search Optimization, warehouses séparés, resource monitor |
| Architecture | Médaillon RAW/SILVER/GOLD, isolation des charges |

## Détection : les 4 types d'attaque

`TYPOSQUATTING` (distance d'édition ≤ 2 : `bnpparibaz.com`), `COMBOSQUATTING` (marque + mot rassurant : `bnpparibas-secure.net`), `HOMOGLYPH` (leetspeak/caractères proches : `paypa1.com`, `rn`→`m`), `BRAND_ABUSE` (marque en sous-chaîne : `login.bnpparibas.evil.io`). Score 0-100 pondéré, seuil d'alerte à 60, sévérité CRITICAL/HIGH/MEDIUM. Les domaines légitimes des marques sont whitelistés.

## Structure

```
pyproject.toml       Dépendances + métadonnées projet (gérées avec uv)
config/brands.yml    Référentiel marques + seuils
ingest/ct_poller.py  Collecteur CT (RFC 6962) + parsing X.509 + PUT Snowflake
sql/00→50            Infra, RBAC, RAW, SILVER, GOLD, gouvernance, share
docs/                Spécification complète (PDF)
```

## Sources de données

CT logs publics interrogés à la source (API RFC 6962), découverts via la [liste officielle Chrome](https://www.gstatic.com/ct/log_list/v3/log_list.json). Marques protégées : domaines officiels publics des banques françaises. Aucune donnée fictive, aucun service tiers.
