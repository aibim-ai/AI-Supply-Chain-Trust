use serde_json::Value;
use thiserror::Error;
use tracing::{info, warn};

use crate::fact_checker::{rejected_output, verify_llm_output, FactCheckError};
use crate::llm_client::{LlmClient, LlmUnavailableError};

#[derive(Debug, Error)]
pub enum GuardrailError {
    #[error(transparent)]
    Unavailable(#[from] LlmUnavailableError),
    #[error(transparent)]
    Rejected(#[from] FactCheckError),
}

#[derive(Clone)]
pub struct LlmGuardrail {
    client: LlmClient,
}

impl LlmGuardrail {
    pub fn from_env() -> Result<Self, LlmUnavailableError> {
        Ok(Self {
            client: LlmClient::shared_from_env()?,
        })
    }

    pub fn new(client: LlmClient) -> Self {
        Self { client }
    }

    pub async fn decide(
        &self,
        task: &str,
        system_prompt: &str,
        input: &Value,
        output_schema: &Value,
    ) -> Result<Value, GuardrailError> {
        let response = self
            .client
            .chat_json_schema(task, system_prompt, input, output_schema)
            .await?;
        let mut output = response.output;
        match verify_llm_output(input, &output) {
            Ok(result) => {
                if let Some(obj) = output.as_object_mut() {
                    obj.insert(
                        "decision_source".into(),
                        Value::String("llm_verified".into()),
                    );
                    obj.insert("model".into(), Value::String(response.model));
                    obj.insert("task".into(), Value::String(task.to_string()));
                    obj.insert(
                        "latency_ms".into(),
                        Value::Number(serde_json::Number::from(response.latency_ms)),
                    );
                    obj.insert(
                        "attempts".into(),
                        Value::Number(serde_json::Number::from(response.attempts)),
                    );
                    obj.insert(
                        "checked_claims".into(),
                        Value::Number(serde_json::Number::from(result.checked_claims)),
                    );
                    obj.insert(
                        "input_hash".into(),
                        Value::String(crate::llm_client::input_hash(input)),
                    );
                }
                info!(task, "LLM output accepted by deterministic guardrail");
                Ok(output)
            }
            Err(err) => {
                warn!(task, error = %err, input = %input, output = %output, "LLM output rejected by deterministic guardrail");
                Err(GuardrailError::Rejected(err))
            }
        }
    }

    pub fn rejected_value(input: &Value, output: &Value, reason: &str) -> Value {
        rejected_output(input, output, reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm_client::LlmClientConfig;
    use serde_json::json;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn guardrail_for(output: Value) -> LlmGuardrail {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let body = json!({
            "choices": [{"message": {"content": output.to_string()}}]
        })
        .to_string();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 8192];
            let _ = socket.read(&mut request).await.unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        });
        let client = LlmClient::new(LlmClientConfig {
            api_key: "test-key".into(),
            endpoint_url: format!("http://{address}/chat"),
            primary_model: "test/model".into(),
            secondary_model: None,
            timeout: Duration::from_secs(1),
            max_retries: 0,
            requests_per_minute: 10,
            requests_per_day: 10,
            retry_base_delay: Duration::from_millis(1),
            retry_max_delay: Duration::from_millis(10),
            circuit_failure_threshold: 3,
            circuit_cooldown: Duration::from_secs(1),
            max_input_bytes: 65_536,
            fallback_max_total_attempts: 4,
            fallback_max_total_latency: Duration::from_secs(5),
            require_non_free_model: false,
        })
        .unwrap();
        LlmGuardrail::new(client)
    }

    #[tokio::test]
    async fn decide_enriches_grounded_output_with_audit_fields() {
        let input = json!({"evidence": [{"id": "commit_1", "sha": "abcdef123456"}]});
        let guardrail = guardrail_for(json!({
            "status": "classified",
            "evidence_refs": ["commit_1"],
            "rationale": "abcdef123456"
        }))
        .await;

        let output = guardrail
            .decide("classify", "evidence only", &input, &json!({}))
            .await
            .unwrap();

        assert_eq!(output["decision_source"], json!("llm_verified"));
        assert_eq!(output["model"], json!("test/model"));
        assert_eq!(output["task"], json!("classify"));
        assert_eq!(output["checked_claims"], json!(1));
        assert!(output["input_hash"]
            .as_str()
            .is_some_and(|value| value.len() == 64));
    }

    #[tokio::test]
    async fn decide_rejects_hallucination_and_rejected_value_is_auditable() {
        let input = json!({"evidence": [{"id": "commit_1"}]});
        let invented = json!({
            "status": "classified",
            "evidence_refs": ["commit_1"],
            "rationale": "CVE-2026-9999"
        });
        let guardrail = guardrail_for(invented.clone()).await;

        assert!(matches!(
            guardrail
                .decide("classify", "evidence only", &input, &json!({}))
                .await,
            Err(GuardrailError::Rejected(_))
        ));
        let rejected = LlmGuardrail::rejected_value(&input, &invented, "invented CVE");
        assert_eq!(rejected["decision_source"], json!("rejected_hallucination"));
        assert_eq!(rejected["reason"], json!("invented CVE"));
    }
}
