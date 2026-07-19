// transport.rs — نقل البيانات من السيرفر
//
// وظيفتان:
//   1. HTTP GET /filter/latest  — تحميل الفلتر الكامل عند التشغيل
//   2. SSE     /filter/updates  — استقبال delta بشكل مستمر
//
// كلاهما يمرران البيانات لـ DeltaEngine للتحقق والتطبيق.

use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn, error};
use reqwest::Client;
use futures::StreamExt;
use serde::Deserialize;

use crate::state::BrxonState;
use crate::delta::{DeltaEngine, DeltaError};
use crate::signing::SignedDelta;

// ─────────────────────────────────────────────────────────────────────────────
//  إعدادات الشبكة
// ─────────────────────────────────────────────────────────────────────────────

const INITIAL_RETRY_DELAY: Duration = Duration::from_secs(5);
const MAX_RETRY_DELAY:     Duration = Duration::from_secs(300); // 5 دقائق
const SSE_RECONNECT_BASE:  Duration = Duration::from_secs(3);

// ─────────────────────────────────────────────────────────────────────────────
//  استجابة /filter/latest
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct FullFilterResponse {
    #[serde(with = "base64_bytes")]
    pub filter_bytes: Vec<u8>,
    pub sha256:       String,
    pub signature:    String,
    pub version:      u64,
    pub m:            usize,   // حجم البتات
    pub k:            u32,     // عدد دوال hash
}

// ─────────────────────────────────────────────────────────────────────────────
//  Transport
// ─────────────────────────────────────────────────────────────────────────────

pub struct Transport {
    state:  Arc<BrxonState>,
    client: Client,
    engine: Arc<DeltaEngine>,
}

impl Transport {
    pub fn new(state: Arc<BrxonState>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .gzip(true)
            .build()
            .expect("فشل بناء HTTP client");

        let engine = Arc::new(DeltaEngine::new(Arc::clone(&state)));

        Self { state, client, engine }
    }

    // ── 1. تحميل الفلتر الكامل عند التشغيل ───────────────────────────────────

    /// يحاول تحميل /filter/latest مع إعادة المحاولة (Exponential Backoff).
    /// يُحجب حتى ينجح أو يُلغى.
    pub async fn load_full_filter(&self) {
        let url = format!("{}/filter/latest", self.state.server_base);
        let mut delay = INITIAL_RETRY_DELAY;

        loop {
            info!("Brxon: جلب الفلتر الكامل من {}", url);

            match self.client.get(&url).send().await {
                Err(e) => {
                    warn!("Brxon: فشل HTTP GET — {} — إعادة بعد {:?}", e, delay);
                    sleep(delay).await;
                    delay = (delay * 2).min(MAX_RETRY_DELAY);
                    continue;
                }
                Ok(resp) => {
                    if !resp.status().is_success() {
                        warn!("Brxon: HTTP {} — إعادة بعد {:?}", resp.status(), delay);
                        sleep(delay).await;
                        delay = (delay * 2).min(MAX_RETRY_DELAY);
                        continue;
                    }

                    match resp.json::<FullFilterResponse>().await {
                        Err(e) => {
                            warn!("Brxon: خطأ في تحليل الاستجابة — {} — إعادة بعد {:?}", e, delay);
                            sleep(delay).await;
                            delay = (delay * 2).min(MAX_RETRY_DELAY);
                        }
                        Ok(full) => {
                            match self.engine.load_full_filter(
                                full.filter_bytes,
                                full.version,
                                full.k,
                                &full.sha256,
                                &full.signature,
                            ) {
                                Ok(()) => {
                                    info!("Brxon: فلتر كامل محمّل — إصدار={}", full.version);
                                    return; // نجاح — نخرج من الحلقة
                                }
                                Err(DeltaError::VerificationFailed(e)) => {
                                    // فشل التحقق = خطر أمني → أعد المحاولة من سيرفر موثوق
                                    error!("Brxon: فشل أمني في الفلتر الكامل — {}", e);
                                    sleep(delay).await;
                                    delay = (delay * 2).min(MAX_RETRY_DELAY);
                                }
                                Err(e) => {
                                    warn!("Brxon: خطأ في التحميل — {} — إعادة بعد {:?}", e, delay);
                                    sleep(delay).await;
                                    delay = (delay * 2).min(MAX_RETRY_DELAY);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // ── 2. SSE — التحديثات المستمرة ───────────────────────────────────────────

    /// حلقة SSE لا تنتهي.
    /// تستمع لـ /filter/updates وتطبّق كل delta واردة.
    /// عند انقطاع الاتصال: إعادة الاتصال تلقائياً بـ Exponential Backoff.
    pub async fn listen_sse(&self) {
        let url = format!("{}/filter/updates", self.state.server_base);
        let mut reconnect_delay = SSE_RECONNECT_BASE;

        loop {
            info!("Brxon: فتح SSE → {}", url);

            match self.client.get(&url)
                .header("Accept", "text/event-stream")
                .header("Cache-Control", "no-cache")
                .send()
                .await
            {
                Err(e) => {
                    warn!("Brxon: فشل اتصال SSE — {} — إعادة بعد {:?}", e, reconnect_delay);
                    sleep(reconnect_delay).await;
                    reconnect_delay = (reconnect_delay * 2).min(MAX_RETRY_DELAY);
                    continue;
                }
                Ok(resp) => {
                    if !resp.status().is_success() {
                        warn!("Brxon: SSE HTTP {} — إعادة بعد {:?}", resp.status(), reconnect_delay);
                        sleep(reconnect_delay).await;
                        reconnect_delay = (reconnect_delay * 2).min(MAX_RETRY_DELAY);
                        continue;
                    }

                    info!("Brxon: SSE متصل — انتظار delta...");
                    reconnect_delay = SSE_RECONNECT_BASE; // إعادة تعيين عند النجاح

                    // معالجة دفق SSE
                    let mut stream = resp.bytes_stream();
                    let mut buffer = String::new();

                    while let Some(chunk) = stream.next().await {
                        match chunk {
                            Err(e) => {
                                warn!("Brxon: انقطع دفق SSE — {}", e);
                                break; // اخرج للحلقة الخارجية لإعادة الاتصال
                            }
                            Ok(bytes) => {
                                if let Ok(text) = std::str::from_utf8(&bytes) {
                                    buffer.push_str(text);
                                    self.process_sse_buffer(&mut buffer);
                                }
                            }
                        }
                    }

                    warn!("Brxon: انقطع SSE — إعادة الاتصال بعد {:?}", reconnect_delay);
                    sleep(reconnect_delay).await;
                    reconnect_delay = (reconnect_delay * 2).min(MAX_RETRY_DELAY);
                }
            }
        }
    }

    // ── معالجة SSE buffer ─────────────────────────────────────────────────────

    /// يُحلّل الرسائل الكاملة من buffer SSE ويطبّق كل delta.
    /// رسالة SSE كاملة تنتهي بـ "\n\n"
    fn process_sse_buffer(&self, buffer: &mut String) {
        while let Some(event_end) = buffer.find("\n\n") {
            let event_text = buffer[..event_end].to_string();
            buffer.drain(..event_end + 2);

            // استخرج نوع الحدث والبيانات
            let mut event_type = String::new();
            let mut data       = String::new();

            for line in event_text.lines() {
                if let Some(val) = line.strip_prefix("event: ") {
                    event_type = val.trim().to_string();
                } else if let Some(val) = line.strip_prefix("data: ") {
                    data = val.trim().to_string();
                }
            }

            if event_type != "filter_update" {
                continue; // تجاهل أحداث أخرى (heartbeat مثلاً)
            }

            if data.is_empty() {
                warn!("Brxon: حدث filter_update بدون بيانات");
                continue;
            }

            // حلّل JSON
            match serde_json::from_str::<SignedDelta>(&data) {
                Err(e) => {
                    warn!("Brxon: خطأ في JSON delta — {}", e);
                }
                Ok(delta) => {
                    let from = delta.from_version;
                    let to   = delta.to_version;
                    match self.engine.apply(&delta) {
                        Ok(()) => {
                            info!("Brxon: Delta {} → {} مطبّق ✓", from, to);
                        }
                        Err(DeltaError::EngineFrozen { .. }) => {
                            // المحرك مجمّد — أوقف معالجة SSE
                            warn!("Brxon: محرك مجمّد — توقف عن معالجة SSE");
                            return;
                        }
                        Err(e) => {
                            error!("Brxon: فشل تطبيق Delta {} → {} — {}", from, to, e);
                        }
                    }
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  سيريلايزيشن مساعد — base64 ↔ Vec<u8>
// ─────────────────────────────────────────────────────────────────────────────

mod base64_bytes {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}
