/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef IAM_LOGGER_H
#define IAM_LOGGER_H

#include "hilog/log.h"

namespace OHOS {
namespace UserIAM {
namespace Utils {
using namespace OHOS::HiviewDFX;

#ifdef __FILE_NAME__
#define FILE __FILE_NAME__
#else
#define FILE (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)
#endif

#ifdef LOG_LABEL
#undef LOG_LABEL
#endif

#define ARGS(fmt, ...) "[%{public}s@%{public}s:%{public}d] " fmt, __FUNCTION__, FILE, __LINE__, ##__VA_ARGS__
#define IAM_LOGD(...) HiLog::Debug(LOG_LABEL, ARGS(__VA_ARGS__))
#define IAM_LOGI(...) HiLog::Info(LOG_LABEL, ARGS(__VA_ARGS__))
#define IAM_LOGW(...) HiLog::Warn(LOG_LABEL, ARGS(__VA_ARGS__))
#define IAM_LOGE(...) HiLog::Error(LOG_LABEL, ARGS(__VA_ARGS__))
#define IAM_LOGF(...) HiLog::Fatal(LOG_LABEL, ARGS(__VA_ARGS__))

static constexpr unsigned int IAM_DOMAIN_ID = 0xD002910;

static constexpr HiLogLabel LABEL_IAM_UTILS = {LOG_CORE, IAM_DOMAIN_ID, "IAM_UTILS"};
static constexpr HiLogLabel LABEL_IAM_BASE = {LOG_CORE, IAM_DOMAIN_ID, "IAM_BASE"};
static constexpr HiLogLabel LABEL_IAM_PIN_AUTH = {LOG_CORE, IAM_DOMAIN_ID, "IAM_PINAUTH"};
static constexpr HiLogLabel LABEL_IAM_FACE_AUTH = {LOG_CORE, IAM_DOMAIN_ID, "IAM_FACEAUTH"};
} // namespace Utils
} // namespace UserIAM
} // namespace OHOS

#endif // IAM_LOGGER_H