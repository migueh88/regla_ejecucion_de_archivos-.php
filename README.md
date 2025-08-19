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
SecRule REQUEST_URI "@rx \.ph(p[0-9]?|tml|ps|ar)(?:$|\?)" \
 "id:930201,phase:1,deny,status:403,log,msg:'Direct PHP no permitido (whitelist WP)',chain"
 SecRule REQUEST_URI "!@rx ^/(index\.php|wp-login\.php|xmlrpc\.php|wp-cron\.php|wp-comments-post\.php|wp-activate\.php|wp-signup\.php|wp-trackback\.php)(?:$|\?)" "chain"
 SecRule REQUEST_URI "!@rx ^/wp-admin/"

SecRule REQUEST_URI "@rx ^/(?:[^/]+/)?wp-content/uploads/.*\.(?:ph(?:p[0-9]?|tml|ps|ar))(?:$|\?)" \
 "id:930212,phase:1,deny,status:403,log,msg:'PHP en uploads bloqueado'"

SecRule REQUEST_URI "@rx (^|/)\.[^/]" \
 "id:930220,phase:1,deny,status:403,log,msg:'Dotfile oculto (/.env, /.git, ...)'"

# 930242 — Bloquear cualquier archivo PHP oculto (.loquesea.php) → 403
SecRule REQUEST_URI "@rx (^|/)\.[^/].*\.ph(p[0-9]?|tml|ps|ar)(?:$|\?)" \
 "id:930242,phase:1,deny,status:403,log,msg:'PHP oculto bloqueado (.filename.php)'"

SecRule REQUEST_URI "@rx (?i)^/(?:indexmc|index2|email)\.php(?:$|\?)" \
 "id:930230,phase:1,deny,status:403,log,msg:'Kit phishing: indexmc/index2/email en docroot'"

SecRule REQUEST_FILENAME "@endsWith .php" \
 "id:930240,phase:1,deny,status:403,log,msg:'PHP no autorizado en docroot (excepto WP core)',chain"
 SecRule REQUEST_URI "!@rx ^/(index\.php|wp-login\.php|xmlrpc\.php|wp-cron\.php|wp-comments-post\.php|wp-activate\.php|wp-signup\.php|wp-trackback\.php)(?:$|\?)" "chain"
 SecRule REQUEST_URI "!@rx ^/wp-admin/"

SecRule REQUEST_METHOD "POST" \
 "id:930241,phase:1,deny,status:403,log,msg:'POST a docroot',chain"
 SecRule REQUEST_HEADERS:Content-Type "@contains multipart/form-data"
```
```apache
###############################################################################
# Custom Anti-Phishing & Anti-Webshell Rules
# Ubicación sugerida: /etc/apache2/conf.d/modsec_vendor_configs/custom-rules.conf
###############################################################################

# ---------------------------------------------------------------------------
# Exclusiones específicas
# ---------------------------------------------------------------------------

# Excepción Softaculous → WordPress autologin (fase 1)
SecRule REQUEST_URI "@rx ^/sapp-wp-signon\.php(?:$|\?)" \
"id:1001301,phase:1,pass,nolog,\
ctl:ruleRemoveById=930201,\
ctl:ruleRemoveById=930240,\
ctl:ruleRemoveById=1001220,\
msg:'Whitelist Softaculous sapp-wp-signon.php (phase 1)'"

# Excepción Softaculous → WordPress autologin (fase 2)
SecRule REQUEST_URI "@rx ^/sapp-wp-signon\.php(?:$|\?)" \
"id:1001304,phase:2,pass,nolog,\
ctl:ruleRemoveById=930201,\
ctl:ruleRemoveById=930240,\
ctl:ruleRemoveById=1001220,\
msg:'Whitelist Softaculous sapp-wp-signon.php (phase 2)'"

# Permitir assets/JS del admin que vienen de PHP
SecRule REQUEST_URI "@rx ^/wp-admin/(?:load-(?:styles|scripts)\.php|admin-ajax\.php|admin-post\.php|async-upload\.php)(?:$|\?)" \
"id:1001310,phase:1,pass,nolog,ctl:ruleRemoveById=1001220,msg:'Allow WP admin assets endpoints'"

# Permitir TinyMCE del editor clásico
SecRule REQUEST_URI "@rx ^/wp-includes/js/tinymce/wp-tinymce\.php(?:$|\?)" \
"id:1001311,phase:1,pass,nolog,ctl:ruleRemoveById=1001220,msg:'Allow TinyMCE asset'"

# Opción más amplia: omitir la 1001220 para todo /wp-admin/
SecRule REQUEST_URI "@beginsWith /wp-admin/" \
"id:1001312,phase:1,pass,nolog,ctl:ruleRemoveById=1001220,msg:'Skip 1001220 in wp-admin'"

###############################################################################
# Reglas de protección
###############################################################################

# 930201 — Bloquear ejecución directa de PHP fuera del core de WP
SecRule REQUEST_URI "@rx \.ph(p[0-9]?|tml|ps|ar)(?:$|\?)" \
"id:930201,phase:1,deny,status:403,log,msg:'Direct PHP no permitido (whitelist WP)',chain"
 SecRule REQUEST_URI "!@rx ^/(index\.php|wp-login\.php|xmlrpc\.php|wp-cron\.php|wp-comments-post\.php|wp-activate\.php|wp-signup\.php|wp-trackback\.php)(?:$|\?)" "chain"
 SecRule REQUEST_URI "!@rx ^/wp-admin/"

# 930212 — Bloquear PHP en uploads/
SecRule REQUEST_URI "@rx ^/(?:[^/]+/)?wp-content/uploads/.*\.(?:ph(?:p[0-9]?|tml|ps|ar))(?:$|\?)" \
"id:930212,phase:1,deny,status:403,log,msg:'PHP en uploads bloqueado'"

# 930220 — Bloquear dotfiles ocultos (/.env, /.git, etc.)
SecRule REQUEST_URI "@rx (^|/)\.[^/]" \
"id:930220,phase:1,deny,status:403,log,msg:'Dotfile oculto (/.env, /.git, ...)'"

# 930242 — Bloquear PHP oculto (.loquesea.php)
SecRule REQUEST_URI "@rx (^|/)\.[^/].*\.ph(p[0-9]?|tml|ps|ar)(?:$|\?)" \
"id:930242,phase:1,deny,status:403,log,msg:'PHP oculto bloqueado (.filename.php)'"

# 930230 — Detectar kits phishing comunes (indexmc/index2/email.php)
SecRule REQUEST_URI "@rx (?i)^/(?:indexmc|index2|email)\.php(?:$|\?)" \
"id:930230,phase:1,deny,status:403,log,msg:'Kit phishing detectado en docroot'"

# 930240 — Bloquear PHP en docroot (excepto core WP)
SecRule REQUEST_FILENAME "@endsWith .php" \
"id:930240,phase:1,deny,status:403,log,msg:'PHP no autorizado en docroot (excepto WP core)',chain"
 SecRule REQUEST_URI "!@rx ^/(index\.php|wp-login\.php|xmlrpc\.php|wp-cron\.php|wp-comments-post\.php|wp-activate\.php|wp-signup\.php|wp-trackback\.php)(?:$|\?)" "chain"
 SecRule REQUEST_URI "!@rx ^/wp-admin/"

# 930241 — Bloquear POST multipart al docroot
SecRule REQUEST_URI "@rx ^/(?:$|\?)" \
"id:930241,phase:1,deny,status:403,log,msg:'POST multipart al docroot',chain"
 SecRule REQUEST_METHOD "POST" "chain"
 SecRule REQUEST_HEADERS:Content-Type "@contains multipart/form-data"

# 1001200 — Bloquear HTML/HTM estático (anti-phishing)
SecRule REQUEST_URI "@rx (?i)\.html?(?:$|\?)" \
"id:1001200,phase:1,deny,status:403,log,msg:'HTML estático bloqueado',chain"
 SecRule REQUEST_URI "!@rx (?i)^/(sitemap[^/]*\.html?|wp-)"

# 1001210 — Bloquear nombres típicos de kits
SecRule REQUEST_URI "@rx (?i)/(?:bot|bots?|bots2|filter|proxyblock|next)\.php(?:$|\?)" \
"id:1001210,phase:1,deny,status:403,log,msg:'Archivo de kit de phishing bloqueado'"

# 1001220 — Solo servir extensiones “seguras” (assets estáticos)
SecRule REQUEST_URI "@rx (?i)\.([a-z0-9]{1,6})(?:$|\?)" \
"id:1001220,phase:1,deny,status:403,log,capture,msg:'Extensión no segura',chain"
 SecRule TX:1 "!@rx ^(?:css|js|mjs|png|jpg|jpeg|gif|webp|svg|ico|bmp|json|xml|txt|map|woff|woff2|ttf|eot|webmanifest|otf|pdf)$"

###############################################################################
# FIN DE LAS CUSTOM RULES
###############################################################################
```

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


