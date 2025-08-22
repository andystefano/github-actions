# CodeQL Configuration Personalizada

Este directorio contiene la configuración personalizada de CodeQL para detectar vulnerabilidades de seguridad específicas en tu proyecto.

## Archivos Incluidos

### `codeql-config.yml`
Archivo de configuración principal que define:
- Consultas de seguridad estándar (`security-and-quality`)
- Consultas personalizadas a través de `custom-queries.qls`
- Paths a incluir/excluir
- Filtros de consultas

### `queries/custom-queries.qls`
Archivo de definición de consultas personalizadas que referencia:
- `env-file-detection.ql` - Detección de archivos .env

### `queries/env-file-detection.ql`
Consulta personalizada que detecta:
- Archivos `.env` y variantes (`.env.local`, `.env.production`, etc.)
- Contenido potencialmente sensible
- Clasificación de severidad basada en el contenido

### `queries/env-file-detection.qhelp`
Documentación de ayuda para la consulta personalizada.

## Cómo Funciona

1. **Detección de Archivos**: Identifica archivos con nombres que contengan "env" o extensión ".env"
2. **Análisis de Contenido**: Busca patrones de variables de entorno sensibles
3. **Clasificación de Severidad**: 
   - **Alta**: Si contiene información sensible detectada
   - **Media**: Si es un archivo .env sin contenido sensible detectado

## Patrones Detectados

La consulta busca variables de entorno que contengan:
- `API_KEY`, `SECRET`, `PASSWORD`, `TOKEN`
- `DATABASE_URL`, `MONGODB_URI`, `JWT_SECRET`
- `AWS_`, `GOOGLE_`, `FACEBOOK_`, `TWITTER_`
- `GITHUB_`, `STRIPE_`, `PAYPAL_`

## Estructura de Archivos

```
.github/codeql/
├── codeql-config.yml          # Configuración principal
├── queries/
│   ├── custom-queries.qls    # Definición de consultas
│   ├── env-file-detection.ql # Consulta personalizada
│   └── env-file-detection.qhelp # Documentación
└── README.md                  # Este archivo
```

## Personalización

Puedes modificar la consulta para:
- Agregar más patrones de detección en `containsSensitiveEnvVars`
- Cambiar los niveles de severidad
- Incluir/excluir tipos específicos de archivos

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

Si encuentras errores:
1. Verifica que todos los archivos estén en las ubicaciones correctas
2. Asegúrate de que las rutas en `codeql-config.yml` sean correctas
3. Revisa que los archivos `.ql` tengan la sintaxis correcta
4. Confirma que el archivo `.qls` esté bien formateado
