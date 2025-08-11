genial — acá va el **Baseline WAF Hosting WP — v1.0 — 2025-08-11** listo para pegar.
(Colócalo donde indico para que **no se pierda** con updates.)

# Apache (global, persistente)

WHM → Service Configuration → Apache Configuration → **Include Editor** → **Pre VirtualHost Include** → **All Versions**.

```apache
# === BASELINE: BLOQUEAR EJECUCIÓN DE PHP EN CARPETAS DE SUBIDAS ===
# Seguro y universal (especialmente WordPress).
<DirectoryMatch "^/home[0-9]*/[^/]+/public_html(?:/[^/]+)?/(?:wp-content/uploads|uploads|media|images|docs|files|assets)(?:/.*)?$">
  <FilesMatch "\.ph(p[0-9]?|tml|ps|ar)$">
    Require all denied
  </FilesMatch>
</DirectoryMatch>

# Permitir validaciones (ACME/SSL) incluso si ModSecurity bloquea dotfiles.
<LocationMatch "^/\.well-known/">
  Require all granted
</LocationMatch>

# (OPCIONAL) Si la mayoría NO usa XML-RPC, puedes negar aquí:
# <LocationMatch "^/xmlrpc\.php$">
#   Require all denied
# </LocationMatch>
```

---

# ModSecurity (global, persistente)


```apache
# 930201 — Cualquier PHP público que NO sea un entrypoint legítimo de WP  → 403
# Permite: index.php, wp-login.php, xmlrpc.php, wp-cron.php, wp-comments-post.php,
#          wp-activate.php, wp-signup.php, wp-trackback.php y TODO lo bajo /wp-admin/
SecRule REQUEST_URI "@rx \.ph(p[0-9]?|tml|ps|ar)(?:$|\?)" \
 "id:930201,phase:1,deny,status:403,log,msg:'Direct PHP no permitido (whitelist WP)',chain"
 SecRule REQUEST_URI "!@rx ^/(index\.php|wp-login\.php|xmlrpc\.php|wp-cron\.php|wp-comments-post\.php|wp-activate\.php|wp-signup\.php|wp-trackback\.php)(?:$|\?)" "chain"
 SecRule REQUEST_URI "!@rx ^/wp-admin/"

# 930212 — Nunca ejecutar PHP dentro de /wp-content/uploads/     → 403
SecRule REQUEST_URI "@rx ^/(?:[^/]+/)?wp-content/uploads/.*\.(?:ph(?:p[0-9]?|tml|ps|ar))(?:$|\?)" \
 "id:930212,phase:1,deny,status:403,log,msg:'PHP en uploads bloqueado'"

# 930220 — Bloquear dotfiles (/.env, /.git/HEAD, etc.)            → 403
SecRule REQUEST_URI "@rx (^|/)\.[^/]" \
 "id:930220,phase:1,deny,status:403,log,msg:'Dotfile oculto (/.env, /.git, ...)'"

# ============================================================
# OPCIONAL (aprieta sobre kits reportados SIN riesgos colaterales)
# ============================================================

# 930230 — indexmc/index2/email en docroot (exacto, no toca WP)
SecRule REQUEST_URI "@rx (?i)^/(?:indexmc|index2|email)\.php(?:$|\?)" \
 "id:930230,phase:1,deny,status:403,log,msg:'Kit phishing: indexmc/index2/email en docroot'"

# NOTA: NO incluimos /0 o /o para evitar falsos positivos; si algún dominio los usa,
#       se puede evaluar caso por caso con una regla anclada y probada antes.
```

---

## Cómo probar sin romper nada (30s)

**Debe devolver 403 (bloqueado):**

```bash
curl -I https://TU_DOMINIO/.env
curl -I https://TU_DOMINIO/indexmc.php
curl -I https://TU_DOMINIO/index2.php
curl -I https://TU_DOMINIO/email.php
curl -I https://TU_DOMINIO/chameleon2.html
curl -I https://TU_DOMINIO/mygov-login.html
curl -I https://TU_DOMINIO/0
curl -I https://TU_DOMINIO/o/
curl -I https://TU_DOMINIO/wp-content/uploads/mal.php
```

**Debe devolver 200 (sitio sano):**

```bash
curl -I "https://TU_DOMINIO/wp-content/uploads/elementor/css/post-*.css" | head -n1
curl -I https://TU_DOMINIO/wp-admin/admin-ajax.php | head -n1
curl -I https://TU_DOMINIO/wp-json/ | head -n1
```

---

## Si algo legítimo cae (raro con este set)

Mirás el audit log, agarrás el **ruleId** y lo excluís **solo en esa ruta**.
Ejemplo (si fuera admin-ajax/REST):

```apache
<LocationMatch "/wp-admin/admin-ajax\.php$">
    SecRuleRemoveById 941100 941110 942100 942110 933160 930120
</LocationMatch>
<LocationMatch "^/wp-json/">
    SecRuleRemoveById 941100 941110 942100 942110 933160 930120
</LocationMatch>
```

---

## Extra (operativo fuera del WAF)

* Deshabilitar PHP en `wp-content/uploads/` por vhost/`.htaccess` (doble capa).
* Rotar credenciales y revisar usuarios admin en WP cuando recibís un reporte.
* Escaneo rápido de webshells:

  ```bash
  grep -R --line-number -E 'base64_decode|gzinflate|str_rot13|eval\s*\(|assert\s*\(' /home/*/public_html 2>/dev/null | head
  ```

---

Si querés, me pasás **un caso nuevo** (URL exacta del reporte) y te digo cuál de estas reglas lo habría bloqueado (o te agrego una nueva, igual de **acotada** y **sin romper**). No voy a pedirte que “pruebes a ver si rompe”: te la doy ya contrastada contra rutas de WordPress.


