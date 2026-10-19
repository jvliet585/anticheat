/**
 * Cloudflare Worker: Proxy Ingestion & Formateador de Reportes Anti-Cheat a Discord
 * 
 * Protege tu Discord Webhook para que nunca este expuesto en el cliente de los jugadores.
 */

export default {
  async fetch(request, env) {
    if (request.method !== "POST") {
      return new Response(JSON.stringify({ error: "Metodo no permitido. Solo POST." }), {
        status: 405,
        headers: { "Content-Type": "application/json" }
      });
    }

    const url = new URL(request.url);
    if (url.pathname !== "/report") {
      return new Response(JSON.stringify({ error: "Endpoint no encontrado." }), {
        status: 404,
        headers: { "Content-Type": "application/json" }
      });
    }

    // 1. Validar el token secreto compartido
    const clientToken = request.headers.get("X-Audit-Token");
    const secretToken = env.AUDIT_SECRET_TOKEN || "CAMBIAR_ESTE_TOKEN_SECRETO";

    if (!clientToken || clientToken !== secretToken) {
      return new Response(JSON.stringify({ error: "No autorizado. Token de auditoria invalido." }), {
        status: 401,
        headers: { "Content-Type": "application/json" }
      });
    }

    // 2. Parsear el reporte JSON
    let report;
    try {
      report = await request.json();
    } catch (e) {
      return new Response(JSON.stringify({ error: "JSON malformado." }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }

    // 3. Validar Webhook de Discord configurado en las variables de entorno
    const discordWebhookUrl = env.DISCORD_WEBHOOK_URL;
    if (!discordWebhookUrl) {
      return new Response(JSON.stringify({ error: "Variable DISCORD_WEBHOOK_URL no configurada en el Worker." }), {
        status: 500,
        headers: { "Content-Type": "application/json" }
      });
    }

    // 4. Formatear el Embed de Discord (Sin emojis, clasificacion tecnica limpia)
    const discordPayload = buildDiscordEmbed(report);

    // 5. Despachar a Discord
    try {
      const discordRes = await fetch(discordWebhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(discordPayload)
      });

      if (!discordRes.ok) {
        const errText = await discordRes.text();
        return new Response(JSON.stringify({ error: `Discord rechazo el mensaje: ${errText}` }), {
          status: 502,
          headers: { "Content-Type": "application/json" }
        });
      }

      return new Response(JSON.stringify({ success: true, message: "Reporte entregado con exito a Discord." }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    } catch (err) {
      return new Response(JSON.stringify({ error: `Fallo al contactar con Discord: ${err.message}` }), {
        status: 500,
        headers: { "Content-Type": "application/json" }
      });
    }
  }
};

function buildDiscordEmbed(report) {
  const risk = report.risk_score || { total_points: 0, level: "Clean", anomalies: [] };
  
  // Colores Discord por nivel
  const colors = {
    "Clean": 0x2ECC71,          // Verde
    "Inconclusive": 0x95A5A6,   // Gris
    "Suspicious": 0xF1C40F,     // Amarillo
    "HighSuspicion": 0xE67E22,  // Naranja
    "StrongEvidence": 0xE74C3C  // Rojo
  };

  const color = colors[risk.level] || 0x3498DB;

  // Formatear cuentas Steam
  const steamAccountsText = (report.steam_accounts || [])
    .slice(0, 5)
    .map(acc => {
      const recent = acc.most_recent ? "[ACTUAL]" : "";
      const l4d2 = acc.played_l4d2 ? `L4D2: ${acc.l4d2_last_played_str || "Registrado"}` : "Sin registros de L4D2";
      return `- **${acc.persona_name}** (${acc.account_name}) ${recent}\n  SteamID: \`${acc.steam_id_64}\` | ${l4d2}`;
    })
    .join("\n\n") || "Ninguna cuenta detectada";

  // Formatear estado L4D2
  const game = report.process_audit || {};
  let gameStatusText = game.l4d2_running
    ? `**En ejecucion** (PID: \`${game.pid}\`)\n- Memoria no respaldada (unbacked): **${game.unbacked_memory_regions}** (Grandes >64KB: \`${game.unbacked_large_regions || 0}\`, Total: ${Math.round((game.total_unbacked_bytes || 0) / 1024)} KB)\n- Modulos DLL escaneados: **${game.total_modules_scanned}**`
    : `**No activo** (El juego estaba cerrado durante el analisis)`;

  if (game.detected_cheat_names && game.detected_cheat_names.length > 0) {
    const cheatsList = game.detected_cheat_names.map(c => `  * **${c}**`).join("\n");
    gameStatusText += `\n- **CHEATS / MENUS IDENTIFICADOS EN MEMORIA:**\n${cheatsList}`;
  }

  // OS Forensics
  const os = report.os_forensics || {};
  let osText = `- Windows InstallDate: \`${os.windows_install_date_str || "N/A"}\`\n- Prefetch: **${os.prefetch_total_files}** archivos (${os.prefetch_wiped_recently ? "ALERTA: Vaciado anomalo detectado" : "Normal"})\n- Privilegios: **${os.is_admin ? "Administrador (Elevado)" : "Usuario Estandar (Limitado)"}**`;

  if (os.active_injector_processes && os.active_injector_processes.length > 0) {
    const injectorsList = os.active_injector_processes.map(i => `  * **${i}**`).join("\n");
    osText += `\n- **INYECTORES ACTIVOS EN SEGUNDO PLANO:**\n${injectorsList}`;
  }

  if (os.suspicious_prefetch_entries && os.suspicious_prefetch_entries.length > 0) {
    const residuesList = os.suspicious_prefetch_entries.map(r => `  * ${r}`).join("\n");
    osText += `\n- **RESIDUOS EN DISCO (PREFETCH):**\n${residuesList}`;
  }

  // Formatear Anomalias con distincion de naturaleza (En Memoria vs Residuo en Disco vs Anti-Forense)
  let anomaliesText = "No se detectaron anomalias. Sistema aparentemente limpio.";
  if (risk.anomalies && risk.anomalies.length > 0) {
    anomaliesText = risk.anomalies
      .map(a => {
        const typeTag = a.detection_type || a.category || "GENERAL";
        return `**[+${a.points} pts] [${typeTag}]**\n> ${a.description}`;
      })
      .join("\n\n");
  }

  const playerTag = report.player_note ? `[${report.player_note}]` : "[Jugador Anonimo]";

  return {
    content: risk.level === "StrongEvidence" || risk.level === "HighSuspicion"
      ? `**[ALERTA DE SEGURIDAD] Reporte con Alta Puntuacion de Riesgo**`
      : undefined,
    embeds: [
      {
        title: `Auditoria L4D2: ${playerTag}`,
        description: `**Report ID:** \`${report.report_id}\`\n**Equipo:** \`${report.machine_name}\`\n**Fecha:** <t:${Math.floor(Date.now() / 1000)}:F>`,
        color: color,
        fields: [
          {
            name: "Veredicto & Puntuacion",
            value: `**Nivel:** \`${risk.level.toUpperCase()}\`\n**Puntos de Riesgo:** \`${risk.total_points} / 100+\``,
            inline: true
          },
          {
            name: "Left 4 Dead 2",
            value: gameStatusText,
            inline: true
          },
          {
            name: "Forense de Windows",
            value: osText,
            inline: false
          },
          {
            name: "Historial de Cuentas Steam en la PC",
            value: steamAccountsText,
            inline: false
          },
          {
            name: "Indicadores Detectados (Clasificacion Tecnica)",
            value: anomaliesText,
            inline: false
          }
        ],
        footer: {
          text: "L4D2 Community Anti-Cheat - Auditoria bajo demanda autorizada por el jugador"
        }
      }
    ]
  };
}
