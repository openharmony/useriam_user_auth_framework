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

#ifndef IAM_IDENTIFY_CONTEXT_H
#define IAM_IDENTIFY_CONTEXT_H

#include <cstdint>
#include <memory>

#include "base_context.h"
#include "identification.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class IdentifyContext : public BaseContext {
public:
    IdentifyContext(uint64_t contextId, std::shared_ptr<Identification> identify,
        std::shared_ptr<ContextCallback> callback);
    ~IdentifyContext() override = default;
    ContextType GetContextType() const override;

protected:
    bool OnStart() override;
    void OnResult(int32_t resultCode, const std::shared_ptr<Attributes> &scheduleResultAttr) override;
    bool OnStop() override;

private:
    bool UpdateScheduleResult(const std::shared_ptr<Attributes> &scheduleResultAttr,
        Identification::IdentifyResultInfo &resultInfo);
    void InvokeResultCallback(const Identification::IdentifyResultInfo &resultInfo) const;
    std::shared_ptr<Identification> identify_ = nullptr;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_IDENTIFY_CONTEXT_H