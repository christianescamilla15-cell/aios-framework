# Security Policy

## Política de Secretos

Este repositorio sigue prácticas estrictas de manejo de credenciales:

### ❌ Nunca committear
- Archivos `.env` con valores reales
- API keys privadas (OpenAI, Anthropic, Stripe secret, etc.)
- Credenciales de base de datos con password
- Tokens de servicio (`service_role`, service accounts)
- Certificados y llaves privadas (`.pem`, `.key`, `.p12`)
- Firebase Admin SDK credentials (`firebase-adminsdk-*.json`)

### ✅ Seguro de committear
- `.env.example` con placeholders (ej: `API_KEY=your_key_here`)
- Firebase client config (`firebase_options.dart`) — Google lo diseñó público
- Supabase `anon` key — público por diseño, RLS del lado servidor
- URLs públicas de servicios (Supabase project URL)

## Reportar vulnerabilidades

Si encuentras una vulnerabilidad de seguridad, por favor NO abras un issue público.
Contacta directamente a: **christianescamilla15@gmail.com**

## Pre-commit Hook Recomendado

Para prevenir commits accidentales de secretos, instala `gitleaks`:

```bash
# Instalar
brew install gitleaks  # macOS
scoop install gitleaks # Windows

# Pre-commit hook
gitleaks install
```

## Rotación de Secretos

Si se expone accidentalmente un secreto:

1. **Rotar inmediatamente** en el proveedor del servicio
2. **Actualizar** la variable en el servicio que la usa (Vercel/Render)
3. **Limpiar el historial** con `git filter-repo --invert-paths --path <archivo>`
4. **Force push** después de rotar (nunca antes)

## Variables Globales del Proyecto

Ver `.env.example` para la lista completa de variables necesarias.
Las variables reales deben configurarse en:

- **Desarrollo local:** archivo `.env` (ignorado por git)
- **Producción:** Dashboard de Vercel/Render/etc.
