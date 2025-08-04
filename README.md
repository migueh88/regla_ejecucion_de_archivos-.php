✅ Solución correcta en WHM
WHM te permite editar esos archivos de forma segura desde su interfaz, y creará automáticamente pre_virtualhost_global.conf si no existe.

🧩 Pasos para hacerlo desde WHM:
Entra a WHM como root.

En el buscador (arriba a la izquierda), escribe:
👉 Apache Configuration

Haz clic en:
👉 Include Editor

En la sección Pre VirtualHost Include, selecciona:
👉 All Versions

Aparecerá un campo para pegar configuración personalizada.

Pega esta regla:

```bash
<DirectoryMatch "^/home/.*/public_html/(uploads|media|images|docs)">
    <FilesMatch "\.php$">
        Require all denied
    </FilesMatch>
</DirectoryMatch>
```
Haz clic en Update o Save.

Luego, WHM te pedirá reconstruir y reiniciar Apache. Acepta.

✅ Resultado:
WHM va a crear automáticamente el archivo faltante:
/etc/apache2/conf.d/includes/pre_virtualhost_global.conf

Y lo cargará correctamente sin romper configuraciones futuras ni sobrescribirse en actualizaciones.

🔒 Ventajas de hacerlo desde WHM:
Compatible con las actualizaciones automáticas de cPanel.

No se sobrescribe al recompilar Apache con EasyApache.

Más seguro que crear manualmente el archivo desde consola.
