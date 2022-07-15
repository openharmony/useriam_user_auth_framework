/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "auth_message_impl.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
const std::vector<uint8_t> &AuthMessageImpl::GetMsgBuffer(const std::shared_ptr<AuthMessage> &msg)
{
    const static std::vector<uint8_t> empty {};
    auto buff = static_cast<AuthMessageImpl *>(msg.get());
    return buff ? buff->msg_ : empty;
}

std::shared_ptr<AuthMessage> AuthMessage::As(const std::vector<uint8_t> &msg)
{
    return std::make_shared<AuthMessageImpl>(msg);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS