/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef USER_AUTH_MODAL_CLIENT_CALLBACK_H
#define USER_AUTH_MODAL_CLIENT_CALLBACK_H

#include <string>

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserAuthModalClientCallback {
public:
    virtual ~UserAuthModalClientCallback() = default;
    virtual void SendCommand(uint64_t contextId, const std::string &cmdData) = 0;
    virtual bool IsModalInit() = 0;
    virtual bool IsModalDestroy() = 0;

private:
    virtual void CancelAuthentication(uint64_t contextId, int32_t cancelReason) = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_MODAL_CLIENT_CALLBACK_H