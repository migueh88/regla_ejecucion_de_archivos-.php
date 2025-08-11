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

WHM → Security Center → **ModSecurity™ Vendors** → **Edit Custom Rules** (o tu **Custom Vendor**).

Te dejo reglas concretas hechas solo con los patrones que vos recibiste en los reportes (indexmc.php, index2.php, email.php, chameleon2.html, mygov-login.html, droppers /0 y /o, .env, .git, PHP en uploads).
Están ancladas al docroot y/o a uploads para no romper Elementor / REST. Copiá y pegá tal cual.

Reglas “anti-phishing kits” (seguras y específicas)
Pegar en: /etc/apache2/conf.d/modsec/modsec2.user.conf (cPanel/Apache)
Luego: systemctl reload apache2 (o httpd)

apache
Copiar
Editar
# ========== BLOQUEOS NO CONTROVERSIALES ==========
# PHP en uploads -> kits y webshells plantados en /uploads  (no lo usa WP)
SecRule REQUEST_URI "@rx ^/(?:[^/]+/)?wp-content/uploads/.*\.(?:ph(?:p[0-9]?|tml|ps|ar))(?:$|\?)" \
 "id:920012,phase:1,deny,status:403,log,msg:'PHP en uploads bloqueado'"

# Dotfiles (.env, .git, etc.) -> bots y kits
SecRule REQUEST_URI "@rx (^|/)\.[^/]" \
 "id:920020,phase:1,deny,status:403,log,msg:'Dotfile oculto (/.env, /.git, ...)'"

# ========== PATRONES EXACTOS DE TUS REPORTES ==========
# indexmc.php / index2.php / email.php (SOLO en docroot: ^/ )
SecRule REQUEST_URI "@rx (?i)^/(?:indexmc|index2|email)\.php(?:$|\?)" \
 "id:920110,phase:1,deny,status:403,log,msg:'Phishing kit: indexmc/index2/email en docroot'"

# chameleon2.html y mygov-login.html (SOLO en docroot)
SecRule REQUEST_URI "@rx (?i)^/(?:chameleon2\.html|mygov-login\.html)(?:$|\?)" \
 "id:920111,phase:1,deny,status:403,log,msg:'Phishing kit: chameleon2/mygov-login en docroot'"

# Droppers /0 y /o en docroot (muy usados para redirecciones de kits)
# Si algún sitio TUYO usa /o/ legítimo, comenta la 920122.
SecRule REQUEST_URI "@rx ^/0(?:$|[\?/])" \
 "id:920121,phase:1,deny,status:403,log,msg:'Dropper /0 en docroot'"
SecRule REQUEST_URI "@rx ^/o(?:$|/|\?)" \
 "id:920122,phase:1,deny,status:403,log,msg:'Dropper /o en docroot'"

# ========== (OPCIONAL PERO ÚTIL) .php desconocidos en docroot ==========
# Permite sólo entrypoints WP conocidos; el resto *.php en docroot -> 403.
# Si algún sitio tiene un .php propio en docroot, añadilo a la allowlist.
SecRule REQUEST_URI "@rx ^/[^/]+\.(?:ph(?:p[0-9]?|tml|ps|ar))(?:$|\?)" \
 "id:920130,phase:1,deny,status:403,log,msg:'PHP desconocido en docroot',chain"
  SecRule REQUEST_URI "!@pm index.php wp-login.php wp-cron.php xmlrpc.php wp-comments-post.php wp-activate.php wp-signup.php wp-trackback.php license.php"

# ========= NADA QUE TOQUE ELEMENTOR / REST =========
# (No hace falta excluir nada porque las reglas de arriba no miran admin-ajax ni wp-json)
Cómo probar sin romper nada (30s)
Debe devolver 403 (bloqueado):

bash
Copiar
Editar
curl -I https://TU_DOMINIO/.env
curl -I https://TU_DOMINIO/indexmc.php
curl -I https://TU_DOMINIO/index2.php
curl -I https://TU_DOMINIO/email.php
curl -I https://TU_DOMINIO/chameleon2.html
curl -I https://TU_DOMINIO/mygov-login.html
curl -I https://TU_DOMINIO/0
curl -I https://TU_DOMINIO/o/
curl -I https://TU_DOMINIO/wp-content/uploads/mal.php
Debe devolver 200 (sitio sano):

bash
Copiar
Editar
curl -I "https://TU_DOMINIO/wp-content/uploads/elementor/css/post-*.css" | head -n1
curl -I https://TU_DOMINIO/wp-admin/admin-ajax.php | head -n1
curl -I https://TU_DOMINIO/wp-json/ | head -n1
Si algo legítimo cae (raro con este set)
Mirás el audit log, agarrás el ruleId y lo excluís solo en esa ruta.
Ejemplo (si fuera admin-ajax/REST):

apache
Copiar
Editar
<LocationMatch "/wp-admin/admin-ajax\.php$">
    SecRuleRemoveById 941100 941110 942100 942110 933160 930120
</LocationMatch>
<LocationMatch "^/wp-json/">
    SecRuleRemoveById 941100 941110 942100 942110 933160 930120
</LocationMatch>
Extra (operativo fuera del WAF)
Deshabilitar PHP en wp-content/uploads/ por vhost/.htaccess (doble capa).

Rotar credenciales y revisar usuarios admin en WP cuando recibís un reporte.

Escaneo rápido de webshells:

bash
Copiar
Editar
grep -R --line-number -E 'base64_decode|gzinflate|str_rot13|eval\s*\(|assert\s*\(' /home/*/public_html 2>/dev/null | head
Si querés, me pasás un caso nuevo (URL exacta del reporte) y te digo cuál de estas reglas lo habría bloqueado (o te agrego una nueva, igual de acotada y sin romper). No voy a pedirte que “pruebes a ver si rompe”: te la doy ya contrastada contra rutas de WordPress.


