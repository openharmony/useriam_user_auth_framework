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

#ifndef REMOTE_IAM_CALLBACK_H
#define REMOTE_IAM_CALLBACK_H

#include "attributes.h"
#include "iiam_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class RemoteIamCallback : public IIamCallback {
public:
    RemoteIamCallback(std::string &connectionName);
    ~RemoteIamCallback() override;

    int32_t OnResult(int32_t resultCode, const std::vector<uint8_t> &extraInfo) override;
    int32_t OnAcquireInfo(int32_t module, int32_t acquireInfo, const std::vector<uint8_t> &extraInfo) override;

    sptr<IRemoteObject> AsObject() override;

private:
    std::string endPointName_;
    std::string connectionName_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // REMOTE_IAM_CALLBACK_H