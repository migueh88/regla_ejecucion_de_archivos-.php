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

```apache
# ===================================================================
# BASELINE MODSECURITY — v1.0 (IDs 9000xx)  [WHM-friendly]
# ===================================================================

# 900010 — subida de PHP camuflado
SecRule FILES_NAMES "@rx \.(?:ph(?:p[0-9]?|tml|ps|ar)|phps)$" "id:900010,phase:2,deny,status:403,log,msg:'Upload de archivo PHP detectado (baseline)'"

# 900012 — ejecución de PHP en /uploads/* (doble capa con Apache)
SecRule REQUEST_URI "@rx ^/.*/(?:wp-content/uploads|uploads|media|images|docs|files|assets)/.*\.ph(p[0-9]?|tml|ps|ar)$" "id:900012,phase:2,deny,status:403,log,msg:'PHP en carpeta de subidas bloqueado (baseline)'"

# 900020 — dotfiles (bloqueo)
SecRule REQUEST_URI "@rx (^|/)\.[^/]" "id:900020,phase:1,deny,status:403,log,msg:'Hidden dotfile access blocked (baseline)'"
# 900021 — excepción .well-known (permitir validaciones SSL/ACME)
SecRule REQUEST_URI "@beginsWith /.well-known/" "id:900021,phase:1,pass,nolog,ctl:ruleRemoveById=900020"

# 900101 — endpoints típicos de kits de phishing (de tus incidentes)
SecRule REQUEST_URI "@pm index2.php email.php chameleon2.html mygov-login.html /mygv/ /o/ /_1.html /0" "id:900101,phase:2,deny,status:403,log,msg:'Patrón común de phishing (baseline)'"

# 900102 — QS sospechosos (SOLO LOG; luego puedes pasar a deny si no hay FPs)
SecRule REQUEST_URI "@rx (?:\?|&)(?:email=|redirect=|to=|url=)" "id:900102,phase:2,pass,log,msg:'QS sospechoso visto en incidentes (solo log)'"

# 900103 — crawler agresivo Bytespider
SecRule REQUEST_HEADERS:User-Agent "@contains Bytespider" "id:900103,phase:1,deny,status:403,log,msg:'Bytespider crawler bloqueado (baseline)'"

# 900104 — WP: admin-ajax con payloads maliciosos obvios (USAR REGLA ENCADENADA)
SecRule REQUEST_URI "@contains /wp-admin/admin-ajax.php" "id:900104,phase:2,deny,status:403,log,msg:'admin-ajax payload sospechoso (WP)',chain"
SecRule ARGS "@rx (?:base64_decode|eval\s*\(|shell_exec|system\s*\()"

# 900105 — WP: rate-limit en wp-login (20 POST / 5min por IP)
SecAction "id:9001050,phase:1,pass,nolog,initcol:ip=%{REMOTE_ADDR},setvar:ip.wp_login_cnt=+0"
SecRule REQUEST_URI "@endsWith /wp-login.php" "id:9001051,phase:2,pass,log,chain,msg:'WP login tracking'"
 SecRule REQUEST_METHOD "@streq POST" "setvar:ip.wp_login_cnt=+1,expirevar:ip.wp_login_cnt=300"
SecRule IP:wp_login_cnt "@gt 20" "id:9001052,phase:2,deny,status:403,log,msg:'WP login rate-limit (20 POST/5min por IP)'"

# 900106 — (OPCIONAL) bloquear XML-RPC si no lo usas globalmente por Apache
# SecRule REQUEST_URI "@endsWith /xmlrpc.php" "id:900106,phase:1,deny,status:403,log,msg:'XML-RPC deshabilitado (baseline)'"
```

---

# Excepciones por dominio (solo si un cliente lo necesita)

Pégalos en **ModSecurity → Rules** del dominio o en el include del vhost correspondiente.

```apache
# Permitir Bytespider SOLO para un dominio
SecRule REQUEST_HEADERS:User-Agent "@contains Bytespider" \
 "id:990901,phase:1,pass,ctl:ruleRemoveById=900103,log,msg:'Allow Bytespider en este vhost'"

# Permitir XML-RPC en un dominio (si lo bloqueaste globalmente)
<LocationMatch "^/xmlrpc\.php$">
  SecRuleRemoveById 900106
</LocationMatch>

# Excluir dotfiles para una ruta puntual (si un plugin raro lo requiere)
<LocationMatch "^/contact/\.ajax">
  SecRuleRemoveById 900020
</LocationMatch>
```

---

# Después de aplicar

```bash
apachectl -t              # validar sintaxis
/scripts/restartsrv_httpd # reiniciar Apache (cPanel)
```

12–24 h después, chequea actividad:

```bash
grep -Po 'id "\K[0-9]+' /usr/local/apache/logs/modsec_audit.log \
| sort | uniq -c | sort -nr | head -20
```

**Compromiso:** si vuelves a preguntar, me referiré a este mismo **Baseline v1.0**.
Solo agregaríamos una regla nueva si aparece un **patrón de ataque nuevo y recurrente**; el baseline no se toca por capricho.
