Perfecto, acá va la **guía paso a paso segura y compatible con WHM/cPanel** para implementar las reglas de protección sin romper nada:

---

## 🧱 PARTE 1 – Agregar regla Apache para **bloquear PHP en carpetas subidas**

### 🔐 Objetivo:

Evitar que se ejecute cualquier archivo `.php` en rutas como `/wp-content/uploads`, `/media`, `/docs`, etc.

### ✅ Pasos en WHM:

1. Iniciá sesión en **WHM como root**.
2. En el buscador (arriba a la izquierda), escribí:
   👉 **Apache Configuration**
3. Hacé clic en:
   👉 **Include Editor**
4. En la sección **Pre VirtualHost Include**, seleccioná:
   👉 **All Versions**
5. En el cuadro de texto que aparece, pegá esta regla:

```apache
<DirectoryMatch "^/home/.*/public_html/.*/(uploads|media|images|docs|files|assets)">
    <FilesMatch "\.php$">
        Require all denied
    </FilesMatch>
</DirectoryMatch>
```

6. Hacé clic en **Update**.
7. WHM te pedirá **reconstruir y reiniciar Apache**. Aceptá.

---

### 🧠 ¿Qué hace esto?

* Se aplica a **todos los dominios en el servidor**.
* No afecta cPanel, ni WHM, ni sitios legítimos.
* Protege contra ejecución de malware en carpetas donde normalmente no debería haber PHP.

---

## 🛡️ PARTE 2 – Agregar reglas ModSecurity para bloquear rutas y cargas comunes de phishing

### ✅ Pasos:

1. En WHM, buscá:
   👉 **ModSecurity™ Vendors**
2. Hacé clic en el vendor que estés usando (ej: OWASP, cPanel default).
3. En la parte inferior, buscá **“Edit Custom Rules”** o similar.
4. Pegá estas reglas:

```apache
# Habilitar inspección de cuerpo de peticiones POST / archivos subidos
SecRequestBodyAccess On

# Bloqueo de rutas sospechosas típicas de phishing
SecRule REQUEST_URI "@rx ^/(auth|login|secure|verify|confirm|email\.php|index2\.php|_1\.html)" \
 "id:990001,phase:2,deny,status:403,log,msg:'Bloqueo de ruta común de phishing detectada'"

# Bloqueo de cargas de archivos por multipart/form-data (formulario con archivo)
SecRule REQUEST_HEADERS:Content-Type "multipart/form-data" \
 "id:990002,phase:2,t:none,deny,status:403,log,msg:'Bloqueo de intento de subida de archivo sospechoso'"

# Bloqueo de parámetros peligrosos comunes en phishing y redirecciones
SecRule ARGS_NAMES "@rx ^(email|redirect|to)$" \
 "id:990003,phase:2,deny,status:403,log,msg:'Bloqueo de parámetro sospechoso en formulario'"

# Bloqueo de parámetros peligrosos adicionales
SecRule ARGS_NAMES "@rx ^(email|redirect|to|url|target)$" \
 "id:990013,phase:2,deny,status:403,log,msg:'Parámetro sospechoso en URL o formulario'"

# Bloqueo de subida de archivos PHP camuflados (.php, .phtml, etc.)
SecRule FILES_NAMES "@rx \.(php|php3|php4|php5|phtml)$" \
 "id:990010,phase:2,t:none,deny,status:403,log,msg:'Subida de archivo PHP detectada'"

# Bloqueo de acceso directo a archivos .php en URLs (por ejemplo /uploads/invoice.php)
SecRule REQUEST_URI "@rx \.php(\?.*)?$" \
 "id:990012,phase:2,t:none,deny,status:403,log,msg:'Acceso directo a archivo PHP bloqueado'"

# Inspección del contenido del body (eval, base64_decode, shell_exec)
SecRule REQUEST_BODY "@rx (eval\s*\(|base64_decode\s*\(|shell_exec\s*\()" \
 "id:990011,phase:2,t:none,deny,status:403,log,msg:'Contenido sospechoso detectado en body o archivo subido'"
```

5. Guardá los cambios.
6. Reiniciá Apache si te lo solicita.

---

### 🧠 ¿Qué hacen estas reglas?

* Bloquean rutas típicas de phishing aunque el dominio sea nuevo.
* Previenen cargas de formularios con archivos maliciosos.
* Detectan parámetros comunes usados en redirecciones maliciosas (`email=`, `to=`, etc.).

---

## 🔧 PARTE 3 (Opcional pero recomendado) – Bloquear `mail()` desde PHP

### ✅ Cómo hacerlo por WHM o directamente en `php.ini`:

1. En WHM, andá a:
   👉 **Software > MultiPHP INI Editor**
2. Seleccioná una versión de PHP usada en tu servidor.
3. En **Editor de configuración básica**, bajá hasta encontrar:
   👉 `disable_functions`
4. Agregá (o asegurate de que estén) las siguientes funciones:

```
mail, exec, shell_exec, system, passthru, popen, proc_open
```

5. Guardá los cambios.

📌 Alternativa: ponelo directamente en el `php.ini` global o por cuenta, si usás CloudLinux o configuración avanzada.

---

## ✅ Resultado final:

Con estos tres pasos:

* Cortás **la ejecución maliciosa**
* Prevenís **subidas y acceso a rutas fraudulentas**
* Evitás que scripts **envíen spam o phishing**

---

¿Querés que te arme un `.txt` con todo esto listo para guardar como checklist o documentación interna?
