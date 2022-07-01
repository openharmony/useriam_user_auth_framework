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

#include "trace.h"

#include "iam_logger.h"

#define LOG_LABEL UserIAM::Common::LABEL_USER_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace UserAuth {
Trace Trace::trace;

Trace::Trace()
{
    // 注册
    ContextCallbackNotifyListener::GetInstance().AddNotifier(ProcessCredChangeEvent);
    ContextCallbackNotifyListener::GetInstance().AddNotifier(ProcessUserAuthEvent);
    ContextCallbackNotifyListener::GetInstance().AddNotifier(ProcessPinAuthEvent);
}

Trace::~Trace()
{
}

void Trace::ProcessCredChangeEvent(const ContextCallbackNotifyListener::MetaData &metaData)
{
    IAM_LOGI("start to process cred change event");
}

void Trace::ProcessUserAuthEvent(const ContextCallbackNotifyListener::MetaData &metaData)
{
    IAM_LOGI("start to process user auth event");
}

void Trace::ProcessPinAuthEvent(const ContextCallbackNotifyListener::MetaData &metaData)
{
    IAM_LOGI("start to process pin auth event");
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS