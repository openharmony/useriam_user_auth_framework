/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef USERIDM_HILOG_WRAPPER_H
#define USERIDM_HILOG_WRAPPER_H

#include "hilog/log.h"

namespace OHOS {
namespace UserIAM {
namespace UserIDM {
#define filename__            (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)
#define formated__(fmt, ...)    "[%{public}s] %{public}s# " fmt, filename__, __FUNCTION__, ##__VA_ARGS__

#ifdef USERIDM_HILOGF
#undef USERIDM_HILOGF
#endif

#ifdef USERIDM_HILOGE
#undef USERIDM_HILOGE
#endif

#ifdef USERIDM_HILOGW
#undef USERIDM_HILOGW
#endif

#ifdef USERIDM_HILOGI
#undef USERIDM_HILOGI
#endif

#ifdef USERIDM_HILOGD
#undef USERIDM_HILOGD
#endif

enum UserIDMSubModule {
    MODULE_CLIENT = 0,
    MODULE_SERVICE,
    MODULE_COMMON,
    MODULE_JS_NAPI,
    USERIDM_MODULE_BUTT,
};

static constexpr unsigned int BASE_USERIDM_DOMAIN_ID = 0xD002910;

enum UserIDMDomainId {
    USERIDM_INNERKIT_DOMAIN = BASE_USERIDM_DOMAIN_ID + MODULE_CLIENT,
    USERIDM_SERVICE_DOMAIN,
    COMMON_DOMAIN,
    USERIDM_JS_NAPI,
    USERIDM_BUTT,
};

static constexpr OHOS::HiviewDFX::HiLogLabel USERIDM_LABEL[USERIDM_MODULE_BUTT] = {
    {LOG_CORE, USERIDM_INNERKIT_DOMAIN, "UserIDMClient"},
    {LOG_CORE, USERIDM_SERVICE_DOMAIN, "UserIDMService"},
    {LOG_CORE, COMMON_DOMAIN, "UserIDMCommon"},
    {LOG_CORE, USERIDM_JS_NAPI, "UserIDMJSNAPI"},
};

// In order to improve performance, do not check the module range.
// Besides, make sure module is less than USERIDM_MODULE_BUTT.
#define USERIDM_HILOGF(module, ...) (void)OHOS::HiviewDFX::HiLog::Fatal(USERIDM_LABEL[module], formated__(__VA_ARGS__))
#define USERIDM_HILOGE(module, ...) (void)OHOS::HiviewDFX::HiLog::Error(USERIDM_LABEL[module], formated__(__VA_ARGS__))
#define USERIDM_HILOGW(module, ...) (void)OHOS::HiviewDFX::HiLog::Warn(USERIDM_LABEL[module], formated__(__VA_ARGS__))
#define USERIDM_HILOGI(module, ...) (void)OHOS::HiviewDFX::HiLog::Info(USERIDM_LABEL[module], formated__(__VA_ARGS__))
#define USERIDM_HILOGD(module, ...) (void)OHOS::HiviewDFX::HiLog::Debug(USERIDM_LABEL[module], formated__(__VA_ARGS__))

constexpr uint64_t MASK = 0x0000FFFF;
} // namespace UserIDM
} // namespace UserIAM
} // namespace OHOS

#endif // USERIDM_HILOG_WRAPPER_H
