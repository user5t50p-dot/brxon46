// lib.rs — نقطة دخول Brxon
//
// Brxon: درع حجب قابل للتضمين داخل Gecko
//
// يتكوّن من:
//   bloom.rs     — محرك Bloom Filter (بحث فقط)
//   signing.rs   — التحقق Ed25519 + SHA256
//   delta.rs     — تطبيق XOR delta + Rollback
//   transport.rs — HTTP GET + SSE
//   policy.rs    — nsIContentPolicy (قلب المحرك)
//   state.rs     — الحالة المشتركة
//
// دورة الحياة:
//   1. brxon_init()       ← Gecko يُهيّئ المحرك عند التشغيل
//   2. brxon_start()      ← يشغّل tokio runtime + يجلب الفلتر + يفتح SSE
//   3. brxon_should_load()← يُستدعى قبل كل طلب شبكي
//   4. brxon_shutdown()   ← Gecko يوقف المحرك عند الإغلاق

pub mod bloom;
pub mod delta;
pub mod policy;
pub mod signing;
pub mod state;
pub mod transport;
pub mod initial_filter;

use std::sync::Arc;
use std::ffi::CStr;
use std::os::raw::c_char;
use tokio::runtime::Runtime;
use tracing::info;
use ed25519_dalek::VerifyingKey;

use crate::bloom::BLOOM_M_BYTES;
use crate::bloom::BLOOM_K;
use crate::policy::ContentPolicy;
use crate::signing::EMBEDDED_PUBLIC_KEY;
use crate::state::BrxonState;
use crate::transport::Transport;

// ─────────────────────────────────────────────────────────────────────────────
//  BrxonEngine — الكيان الرئيسي
// ─────────────────────────────────────────────────────────────────────────────

/// كائن المحرك الكامل — يُخزَّن في Gecko طوال عمر المتصفح
pub struct BrxonEngine {
    pub policy:  ContentPolicy,
    pub state:   Arc<BrxonState>,
    /// tokio runtime مخصص لـ Brxon (لا يتعارض مع Gecko)
    runtime:     Runtime,
}

impl BrxonEngine {
    /// أنشئ محرك جديد
    ///
    /// `server_base`: عنوان السيرفر مثل "https://filter.example.com"
    pub fn new(server_base: &str) -> Result<Self, String> {
        // تهيئة logging
        let _ = tracing_subscriber::fmt()
            .with_env_filter("brxon=info")
            .try_init();

        // بناء المفتاح العام من الثابت المضمّن
        let public_key = VerifyingKey::from_bytes(&EMBEDDED_PUBLIC_KEY)
            .map_err(|e| format!("مفتاح عام غير صالح: {e}"))?;

        // بناء الحالة المشتركة
        let state = BrxonState::new(
            public_key,
            server_base.to_string(),
            BLOOM_M_BYTES,
            BLOOM_K,
        );

        // بناء سياسة الحجب
        let policy = ContentPolicy::new(Arc::clone(&state));

        // tokio runtime مخصص (multi-thread للـ SSE)
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("brxon-worker")
            .enable_all()
            .build()
            .map_err(|e| format!("فشل بناء tokio runtime: {e}"))?;

        // حمّل الفلتر المضمّن فوراً
        if let Err(e) = crate::initial_filter::load_embedded_filter(&state) {
            eprintln!("Brxon: تحذير — فشل تحميل الفلتر المضمّن: {}", e);
        }

        info!("Brxon: محرك جاهز — سيرفر={}", server_base);

        Ok(Self { policy, state, runtime })
    }

    /// ابدأ التحميل والاستماع في الخلفية (non-blocking)
    pub fn start(&self) {
        let state_clone = Arc::clone(&self.state);

        self.runtime.spawn(async move {
            let transport = Transport::new(Arc::clone(&state_clone));

            // 1. اجلب الفلتر الكامل أولاً (يُحجب حتى ينجح)
            transport.load_full_filter().await;

            info!("Brxon: الفلتر جاهز — بدء الاستماع للتحديثات...");

            // 2. ابدأ SSE (لا ينتهي أبداً)
            transport.listen_sse().await;
        });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  FFI — واجهة C الكاملة للاستدعاء من Gecko
// ─────────────────────────────────────────────────────────────────────────────

/// مؤشر للمحرك — يُعاد لـ Gecko ويُمرَّر في كل استدعاء لاحق
pub type BrxonHandle = *mut BrxonEngine;

/// تهيئة Brxon — يُستدعى مرة واحدة عند تشغيل Gecko
///
/// `server_base`: عنوان السيرفر (UTF-8, null-terminated)
///
/// يُعيد مؤشراً للمحرك أو NULL عند الفشل.
///
/// # Safety
/// `server_base` يجب أن يكون مؤشراً صالحاً لـ null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn brxon_init(server_base: *const c_char) -> BrxonHandle {
    if server_base.is_null() {
        return std::ptr::null_mut();
    }

    let server_str = match CStr::from_ptr(server_base).to_str() {
        Ok(s)  => s,
        Err(_) => return std::ptr::null_mut(),
    };

    match BrxonEngine::new(server_str) {
        Ok(engine) => Box::into_raw(Box::new(engine)),
        Err(e) => {
            eprintln!("Brxon: فشل التهيئة — {}", e);
            std::ptr::null_mut()
        }
    }
}

/// تشغيل Brxon في الخلفية — يُستدعى بعد brxon_init مباشرة
///
/// # Safety
/// `handle` يجب أن يكون مؤشراً صالحاً مُعاداً من brxon_init.
#[no_mangle]
pub unsafe extern "C" fn brxon_start(handle: BrxonHandle) {
    if handle.is_null() { return; }
    (*handle).start();
}

/// فحص URI قبل تحميله — نقطة الدخول الرئيسية
///
/// `handle`       : المؤشر المُعاد من brxon_init
/// `content_type` : نوع الطلب (TYPE_DOCUMENT=6, TYPE_SCRIPT=2, ...)
/// `uri`          : الـ URI كامل (null-terminated C string)
///
/// يُعيد:
///   `BrxonDecision.decision`:
///      1  = ACCEPT
///     -1  = REJECT_REQUEST (رفض صامت — إعلانات/تتبع)
///     -2  = REJECT_TYPE    (رفض مع صفحة — مواقع إباحية)
///
/// # Safety
/// جميع المؤشرات يجب أن تكون صالحة.
#[no_mangle]
pub unsafe extern "C" fn brxon_should_load(
    handle:       BrxonHandle,
    content_type: u32,
    uri:          *const c_char,
) -> policy::BrxonDecision {
    use policy::{BrxonDecision, policy_decision};

    let null_accept = BrxonDecision {
        decision:        policy_decision::ACCEPT,
        show_block_page: false,
    };

    if handle.is_null() || uri.is_null() {
        return null_accept;
    }

    let uri_str = match CStr::from_ptr(uri).to_str() {
        Ok(s)  => s,
        Err(_) => return null_accept,
    };

    let engine  = &*handle;
    let outcome = engine.policy.should_load(content_type, uri_str);

    BrxonDecision {
        decision:        outcome.to_gecko_decision(),
        show_block_page: outcome == policy::PolicyOutcome::RejectWithBlockPage,
    }
}

/// إيقاف المحرك وتحرير الذاكرة — يُستدعى عند إغلاق Gecko
///
/// # Safety
/// `handle` يجب أن يكون مؤشراً صالحاً مُعاداً من brxon_init.
/// بعد هذه الدالة، المؤشر غير صالح ولا يجب استخدامه.
#[no_mangle]
pub unsafe extern "C" fn brxon_shutdown(handle: BrxonHandle) {
    if handle.is_null() { return; }
    info!("Brxon: إيقاف المحرك...");
    // Box::from_raw يتولى تحرير الذاكرة عند نهاية النطاق
    let _ = Box::from_raw(handle);
    info!("Brxon: تم الإيقاف");
}

/// هل الفلتر جاهز للعمل؟ (للاستعلام من Gecko)
///
/// # Safety
/// `handle` يجب أن يكون مؤشراً صالحاً.
#[no_mangle]
pub unsafe extern "C" fn brxon_is_ready(handle: BrxonHandle) -> bool {
    if handle.is_null() { return false; }
    (*handle).state.is_ready()
}

/// رقم إصدار الفلتر الحالي (للإحصاءات)
///
/// # Safety
/// `handle` يجب أن يكون مؤشراً صالحاً.
#[no_mangle]
pub unsafe extern "C" fn brxon_filter_version(handle: BrxonHandle) -> u64 {
    if handle.is_null() { return 0; }
    let h = &*handle; h.state.filter.read().version
}

// ─────────────────────────────────────────────────────────────────────────────
//  كود C++ المرجعي لـ Gecko (تعليقات توضيحية فقط — ليس Rust)
// ─────────────────────────────────────────────────────────────────────────────
//
// // في ملف Gecko (مثلاً: netwerk/base/ThreatBlocker.cpp):
//
// #include "brxon.h"   // header يُنشأ من cbindgen
//
// static BrxonHandle gBrxon = nullptr;
//
// // عند تشغيل المتصفح:
// void ThreatBlocker::Init() {
//     gBrxon = brxon_init("https://filter.example.com");
//     brxon_start(gBrxon);
// }
//
// // في nsIContentPolicy::ShouldLoad():
// NS_IMETHODIMP ThreatBlocker::ShouldLoad(
//     nsIURI* aURI, uint32_t aContentType, ..., int16_t* aDecision)
// {
//     nsAutoCString uri;
//     aURI->GetSpec(uri);
//
//     BrxonDecision result = brxon_should_load(
//         gBrxon,
//         aContentType,
//         uri.get()
//     );
//
//     *aDecision = result.decision;
//
//     if (result.show_block_page) {
//         // وجّه Gecko لتحميل:
//         // chrome://browser/content/blockinfo.html
//     }
//
//     return NS_OK;
// }
//
// // عند إغلاق المتصفح:
// void ThreatBlocker::Shutdown() {
//     brxon_shutdown(gBrxon);
//     gBrxon = nullptr;
// }
