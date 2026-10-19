use crate::models::AuditReport;
use std::time::Duration;

/// Sends the audit report payload to the Cloudflare Worker serverless proxy
pub async fn send_report_to_worker(
    worker_url: &str,
    secret_token: &str,
    report: &AuditReport,
) -> Result<String, String> {
    if worker_url.trim().is_empty() {
        return Err("La URL del Cloudflare Worker no está configurada.".to_string());
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("Error creando cliente HTTP: {}", e))?;

    let response = client
        .post(worker_url)
        .header("Content-Type", "application/json")
        .header("X-Audit-Token", secret_token)
        .json(report)
        .send()
        .await
        .map_err(|e| format!("Fallo al conectar con el Worker: {}", e))?;

    let status = response.status();
    let text = response
        .text()
        .await
        .unwrap_or_else(|_| "Respuesta sin contenido".to_string());

    if status.is_success() {
        Ok(format!("Reporte enviado exitosamente (HTTP {}).", status.as_u16()))
    } else {
        Err(format!(
            "El servidor respondió con error HTTP {}: {}",
            status.as_u16(),
            text
        ))
    }
}

