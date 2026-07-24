# Guía de publicación en npm / Publishing guide

Pasos para publicar `sql-injections` en el registro de npm.

## 1. Requisitos previos

- Tener una cuenta en https://www.npmjs.com
- Node.js >= 18 y npm instalados (`node -v`, `npm -v`)
- Que el nombre `sql-injections` esté disponible o sea tuyo. Compruébalo:

  ```bash
  npm view sql-injections
  ```

  - Si devuelve datos de un paquete que **no** es tuyo, el nombre está tomado:
    cambia `name` en `package.json` (p. ej. a un scope propio
    `@tu-usuario/sql-injections`).
  - Si devuelve `404`, el nombre está libre.

## 2. Antes de publicar

```bash
# 1. Instala (no hay dependencias, pero valida el package.json)
npm install

# 2. Corre las pruebas — también se ejecutan solas por "prepublishOnly"
npm test

# 3. Revisa EXACTAMENTE qué archivos se subirán
npm pack --dry-run
```

Deberían empaquetarse solo: `sql-injections.js`, `lib/`, `README.md`,
`LICENSE`, `CHANGELOG.md` y `package.json` (controlado por el campo `files`).

## 3. Versionado (SemVer)

Usa `npm version` para subir la versión, crear el commit y el tag de git:

```bash
npm version patch   # 1.0.0 -> 1.0.1  (arreglos)
npm version minor   # 1.0.0 -> 1.1.0  (nuevas funciones compatibles)
npm version major   # 1.0.0 -> 2.0.0  (cambios que rompen compatibilidad)
```

La versión inicial ya está en `1.0.0`, así que para el primer publish
puedes saltarte este paso.

## 4. Iniciar sesión y publicar

```bash
# Inicia sesión (abre el navegador para 2FA si lo tienes activado)
npm login

# Verifica quién eres
npm whoami

# Publicación
npm publish
```

> Si usas un nombre con scope (`@tu-usuario/sql-injections`) y quieres que sea
> público, la primera vez añade:
> ```bash
> npm publish --access public
> ```

## 5. Verificar

```bash
npm view sql-injections
```

Y prueba la instalación en una carpeta limpia:

```bash
mkdir /tmp/prueba && cd /tmp/prueba && npm init -y
npm install sql-injections
node -e "console.log(require('sql-injections').hasSql(\"' OR 1=1 --\"))"  # true
```

## 6. Publicar cambios posteriores

1. Actualiza el código y añade una entrada en `CHANGELOG.md`.
2. `npm test`
3. `npm version patch|minor|major`
4. `npm publish`
5. `git push && git push --tags`

## Notas

- **2FA:** se recomienda activar la verificación en dos pasos en tu cuenta npm
  (`Account → Two-Factor Authentication`).
- **Deshacer un publish:** solo puedes retirar (`npm unpublish`) dentro de las
  primeras 72 horas y con condiciones. Publica con cuidado.
- **Correo de contacto:** si quieres un email público para reportes, añádelo en
  `package.json` bajo `bugs.email` o `author` (será visible en npm).
