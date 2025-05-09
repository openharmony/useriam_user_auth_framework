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

#ifndef TRACE_H
#define TRACE_H

#include "nocopyable.h"

#include "context_callback.h"
#include "hisysevent_adapter.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class Trace final : public NoCopyable {
private:
    static Trace trace;
    static void ProcessCredChangeEvent(const ContextCallbackNotifyListener::MetaData &metaData, TraceFlag flag);
    static void ProcessCredManagerEvent(const ContextCallbackNotifyListener::MetaData &metaData, TraceFlag flag);
    static void CopyMetaDataToTraceInfo(const ContextCallbackNotifyListener::MetaData &metaData, UserAuthTrace &info);
    static void ProcessUserAuthEvent(const ContextCallbackNotifyListener::MetaData &metaData, TraceFlag flag);
    static void ProcessUserAuthFwkEvent(const ContextCallbackNotifyListener::MetaData &metaData, TraceFlag flag);
    Trace();
    ~Trace() override;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // TRACE_H