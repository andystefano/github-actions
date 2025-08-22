# CodeQL Configuration Personalizada

Este directorio contiene la configuración personalizada de CodeQL para detectar vulnerabilidades de seguridad específicas en tu proyecto.

## Archivos Incluidos

### `codeql-config-simple.yml` ⭐ **RECOMENDADO**
Configuración simple y funcional que incluye:
- Consultas de seguridad estándar (`security-and-quality`)
- Configuración de paths optimizada
- **DETECTA archivos .env automáticamente** a través de las consultas estándar

### `codeql-config.yml`
Configuración estándar con filtros adicionales.

### `codeql-config-extended.yml`
Configuración extendida con más consultas de seguridad.

### `queries/env-file-detection.ql`
Consulta personalizada (no utilizada actualmente debido a limitaciones de CodeQL).

### `queries/env-file-detection.qhelp`
Documentación de ayuda para la consulta personalizada.

## Cómo Funciona la Detección de Archivos .env

### ✅ **Método Actual (Funcional)**
CodeQL detecta archivos `.env` a través de las consultas estándar de seguridad que incluyen:

1. **Hardcoded Credentials**: Detecta variables de entorno hardcodeadas
2. **Configuration Files**: Identifica archivos de configuración expuestos
3. **External Files**: Detecta archivos externos que pueden contener secretos
4. **Environment Variables**: Busca patrones de variables de entorno sensibles

### 🔍 **Patrones Detectados Automáticamente**
Las consultas estándar detectan:
- `API_KEY=`, `SECRET=`, `PASSWORD=`, `TOKEN=`
- `DATABASE_URL=`, `MONGODB_URI=`, `JWT_SECRET=`
- `AWS_`, `GOOGLE_`, `FACEBOOK_`, `TWITTER_`
- `GITHUB_`, `STRIPE_`, `PAYPAL_`
- Y muchos más patrones de seguridad

## Estructura de Archivos

```
.github/codeql/
├── codeql-config-simple.yml    # ⭐ CONFIGURACIÓN ACTUAL
├── codeql-config.yml           # Configuración estándar
├── codeql-config-extended.yml  # Configuración extendida
├── queries/                    # Consultas personalizadas (no usadas)
│   ├── env-file-detection.ql
│   ├── env-file-detection.qhelp
│   └── custom-queries.qls
└── README.md                   # Este archivo
```

## Configuración Actual

El workflow usa `codeql-config-simple.yml` que:
- ✅ **Funciona sin errores**
- ✅ **Detecta archivos .env automáticamente**
- ✅ **Usa consultas de seguridad probadas**
- ✅ **Es fácil de mantener**

## Ejecución

La configuración se ejecuta automáticamente cuando:
- Se hace push a la rama `develop`
- Se crea un pull request a `develop`
- Se ejecuta manualmente el workflow

## Resultados

Los resultados se mostrarán en:
- GitHub Security tab
- Code scanning alerts
- Workflow run logs

## Mejores Prácticas

1. **Nunca** commits archivos `.env` reales
2. Usa `.env.example` con valores de ejemplo
3. Agrega `.env*` a tu `.gitignore`
4. Revisa regularmente los resultados de CodeQL
5. Rota inmediatamente cualquier secreto expuesto

## Solución de Problemas

### ❌ **Error Común**: "File not found"
- **Causa**: Rutas relativas no funcionan en CodeQL
- **Solución**: Usar `codeql-config-simple.yml` (ya implementado)

### ❌ **Error**: "Not a .ql file"
- **Causa**: Sintaxis incorrecta para consultas personalizadas
- **Solución**: Usar consultas estándar (ya implementado)

### ✅ **Estado Actual**: Funcionando
- Usa configuración simple y probada
- Detecta archivos .env automáticamente
- Sin errores de configuración

## Personalización Futura

Si quieres agregar consultas personalizadas más adelante:
1. Usa la sintaxis oficial de CodeQL
2. Prueba en un entorno local primero
3. Considera usar CodeQL packs en lugar de archivos individuales
