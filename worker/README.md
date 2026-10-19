# Guía de Despliegue: Cloudflare Worker Proxy para Discord

Este Worker actúa como un intermediario seguro entre la herramienta de auditoría de Left 4 Dead 2 y tu servidor de Discord.

### ¿Por qué usamos este Worker?
1. **Protección del Webhook:** La URL secreta de tu canal de Discord nunca se expone dentro del ejecutable que descargan los jugadores.
2. **Prevención de Spam:** Solo peticiones con el token secreto (`X-Audit-Token`) pueden publicar mensajes.
3. **Cero Coste:** El plan gratuito de Cloudflare Workers incluye **100,000 peticiones diarias gratis**, lo que sobra para cualquier comunidad de L4D2.

---

## Pasos para el Despliegue (En 2 Minutos)

### Paso 1: Crear el Worker en Cloudflare
1. Inicia sesión en tu cuenta gratuita de [Cloudflare Dashboard](https://dash.cloudflare.com/).
2. En el menú lateral, dirígete a **Workers & Pages** > **Overview**.
3. Haz clic en **Create Application** > **Create Worker**.
4. Asígnale un nombre (por ejemplo: `l4d2-audit-proxy`) y pulsa en **Deploy**.

### Paso 2: Pegar el Código
1. En la página de tu nuevo Worker, haz clic en **Edit code** (o *Quick edit*).
2. Borra el código por defecto y pega el contenido completo de `worker.js`.
3. Haz clic en **Save and Deploy**.

### Paso 3: Configurar las Variables de Entorno (Secretos)
1. Ve a la pestaña **Settings** de tu Worker > **Variables and Secrets**.
2. Añade las dos siguientes variables:
   * **`DISCORD_WEBHOOK_URL`** (Tipo: *Secret*): Pega la URL de tu Webhook de Discord (creada en la configuración de tu canal de Discord > Integraciones > Webhooks).
   * **`AUDIT_SECRET_TOKEN`** (Tipo: *Secret* o *Plain text*): Escribe una clave secreta que inventes (por ejemplo: `MiClaveSegura2026_L4D2!`).
3. Guarda los cambios.

### Paso 4: Probar y Usar en la App
* La URL pública de tu Worker será:
  `https://l4d2-audit-proxy.<tu-subdominio>.workers.dev/report`
* Abre la pestaña **Servidor / Worker** en la aplicación del anti-cheat, escribe esa URL y el token secreto que definiste.

