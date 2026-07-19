/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "ThreatBlocker.h"
#include "nsIURI.h"
#include "nsILoadInfo.h"
#include "nsAutoCString.h"
#include "nsServiceManagerUtils.h"
#include "nsIObserverService.h"
#include "mozilla/Services.h"
#include "mozilla/Logging.h"
#include "mozilla/ClearOnShutdown.h"
#include "mozilla/StaticPtr.h"
#include "nsNetUtil.h"

namespace mozilla::net {

static LazyLogModule sBrxonLog("Brxon");
static StaticRefPtr<ThreatBlocker> sSingleton;

// ── Singleton ────────────────────────────────────────────────────────────────

already_AddRefed<ThreatBlocker> ThreatBlocker::GetSingleton() {
  if (!sSingleton) {
    sSingleton = new ThreatBlocker();
    sSingleton->Init();
    ClearOnShutdown(&sSingleton);
  }
  return do_AddRef(sSingleton);
}

// ── Init / Shutdown ───────────────────────────────────────────────────────────

void ThreatBlocker::Init() {
  // سيرفر فارغ في النسخة الأولى — الفلتر مضمّن في libbrxon.a
  mHandle = brxon_init("");
  if (mHandle) {
    brxon_start(mHandle);
    MOZ_LOG(sBrxonLog, LogLevel::Info, ("Brxon: محرك الحجب نشط"));
  } else {
    MOZ_LOG(sBrxonLog, LogLevel::Error, ("Brxon: فشل التهيئة"));
  }

  // استمع لحدث الإغلاق
  nsCOMPtr<nsIObserverService> obs = services::GetObserverService();
  if (obs) {
    obs->AddObserver(this, "xpcom-shutdown", false);
  }
}

void ThreatBlocker::Shutdown() {
  if (mHandle) {
    brxon_shutdown(mHandle);
    mHandle = nullptr;
    MOZ_LOG(sBrxonLog, LogLevel::Info, ("Brxon: تم الإيقاف"));
  }
}

ThreatBlocker::~ThreatBlocker() {
  Shutdown();
}

// ── nsIObserver ───────────────────────────────────────────────────────────────

NS_IMETHODIMP
ThreatBlocker::Observe(nsISupports* aSubject,
                       const char*  aTopic,
                       const char16_t* aData)
{
  if (strcmp(aTopic, "xpcom-shutdown") == 0) {
    Shutdown();
  }
  return NS_OK;
}

// ── nsIContentPolicy::ShouldLoad ─────────────────────────────────────────────

NS_IMETHODIMP
ThreatBlocker::ShouldLoad(nsIURI*           aURI,
                           nsILoadInfo*      aLoadInfo,
                           const nsACString& aMimeType,
                           int16_t*          aDecision)
{
  *aDecision = nsIContentPolicy::ACCEPT;

  if (!mHandle || !brxon_is_ready(mHandle)) {
    return NS_OK;
  }

  // استخرج URI
  nsAutoCString uri;
  nsresult rv = aURI->GetSpec(uri);
  if (NS_FAILED(rv)) return NS_OK;

  // نوع الطلب
  uint32_t contentType = aLoadInfo->InternalContentPolicyType();

  // استشر Brxon
  BrxonDecision result = brxon_should_load(mHandle, contentType, uri.get());
  *aDecision = result.decision;

  if (result.show_block_page) {
    MOZ_LOG(sBrxonLog, LogLevel::Info,
            ("Brxon: حجب موقع → about:brxon-block [%s]", uri.get()));
    // وجّه Gecko لصفحة الحجب الخاصة بـ Lotus
    // REJECT_TYPE يجعل Gecko يستبدل الصفحة تلقائياً
    // نمرر URI الأصلي كـ query parameter ليظهر في صفحة الحجب
    nsAutoCString blockURI("about:brxon-block?url=");
    blockURI.Append(uri);
    nsCOMPtr<nsIURI> blockPageURI;
    if (NS_SUCCEEDED(NS_NewURI(getter_AddRefs(blockPageURI), blockURI))) {
      aLoadInfo->SetResultPrincipalURI(blockPageURI);
    }
  }

  return NS_OK;
}

NS_IMETHODIMP
ThreatBlocker::ShouldProcess(nsIURI*, nsILoadInfo*,
                              const nsACString&, int16_t* aDecision)
{
  *aDecision = nsIContentPolicy::ACCEPT;
  return NS_OK;
}

NS_IMPL_ISUPPORTS(ThreatBlocker, nsIContentPolicy, nsIObserver)

} // namespace mozilla::net
