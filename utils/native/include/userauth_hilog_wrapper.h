/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef USERAUTH_HILOG_WRAPPER_H
#define USERAUTH_HILOG_WRAPPER_H

#define CONFIG_HILOG
#ifdef CONFIG_HILOG
#include "hilog/log.h"
namespace OHOS {
namespace UserIAM {
namespace UserAuth {
#define FILENAME            (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)
#define FORMATED(fmt, ...)    "[%{public}s] %{public}s# " fmt, FILENAME, __FUNCTION__, ##__VA_ARGS__

#ifdef USERAUTH_HILOGF
#undef USERAUTH_HILOGF
#endif

#ifdef USERAUTH_HILOGE
#undef USERAUTH_HILOGE
#endif

#ifdef USERAUTH_HILOGW
#undef USERAUTH_HILOGW
#endif

#ifdef USERAUTH_HILOGI
#undef USERAUTH_HILOGI
#endif

#ifdef USERAUTH_HILOGD
#undef USERAUTH_HILOGD
#endif

// param of log interface, such as DISTRIBUTED_GALLERY_HILOGF.
enum UserAuthSubModule {
    MODULE_INNERKIT = 0,
    MODULE_SERVICE,
    MODULE_COMMON,
    MODULE_JS_NAPI,
    USERAUTHS_MODULE_BUTT,
};

// 0xD002900: subsystem:distributeddatamgr module:distributedgallery, 8 bits reserved.
static constexpr unsigned int BASE_USERAUTH_DOMAIN_ID = 0xD002910;

enum UserAuthDomainId {
    USERAUTH_INNERKIT_DOMAIN = BASE_USERAUTH_DOMAIN_ID + MODULE_INNERKIT,
    USERAUTH_SERVICE_DOMAIN,
    COMMON_DOMAIN,
    USERAUTH_JS_NAPI
};

static constexpr OHOS::HiviewDFX::HiLogLabel USERAUTH_LABEL[USERAUTHS_MODULE_BUTT] = {
    {LOG_CORE, USERAUTH_INNERKIT_DOMAIN, "UserAuthClient"},
    {LOG_CORE, USERAUTH_SERVICE_DOMAIN, "UserAuthService"},
    {LOG_CORE, COMMON_DOMAIN, "UserAuthCommon"},
    {LOG_CORE, USERAUTH_JS_NAPI, "UserAuthJSNAPI"},
};

// In order to improve performance, do not check the module range.
// Besides, make sure module is less than DISTRIBUTED_GALLERY_MODULE_BUTT.
#define USERAUTH_HILOGF(module, ...) (void)OHOS::HiviewDFX::HiLog::Fatal(USERAUTH_LABEL[module], FORMATED(__VA_ARGS__))
#define USERAUTH_HILOGE(module, ...) (void)OHOS::HiviewDFX::HiLog::Error(USERAUTH_LABEL[module], FORMATED(__VA_ARGS__))
#define USERAUTH_HILOGW(module, ...) (void)OHOS::HiviewDFX::HiLog::Warn(USERAUTH_LABEL[module], FORMATED(__VA_ARGS__))
#define USERAUTH_HILOGI(module, ...) (void)OHOS::HiviewDFX::HiLog::Info(USERAUTH_LABEL[module], FORMATED(__VA_ARGS__))
#define USERAUTH_HILOGD(module, ...) (void)OHOS::HiviewDFX::HiLog::Debug(USERAUTH_LABEL[module], FORMATED(__VA_ARGS__))
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS

#else

#define USERAUTH_HILOGF(...)
#define USERAUTH_HILOGE(...)
#define USERAUTH_HILOGW(...)
#define USERAUTH_HILOGI(...)
#define USERAUTH_HILOGD(...)

#endif // CONFIG_HILOG

#endif // USERAUTH_HILOG_WRAPPER_H
