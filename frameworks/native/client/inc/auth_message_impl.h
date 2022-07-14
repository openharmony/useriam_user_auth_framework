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

#ifndef AUTH_MESSAGE_H
#define AUTH_MESSAGE_H

#include <vector>

#include "co_auth_client_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class AuthMessageImpl final : public AuthMessage {
public:
    explicit AuthMessageImpl(std::vector<uint8_t> msg) : msg_(std::move(msg)) {};
    virtual ~AuthMessageImpl() = default;
    static const std::vector<uint8_t> &GetMsgBuffer(const std::shared_ptr<AuthMessage> &msg);

private:
    const std::vector<uint8_t> msg_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // AUTH_MESSAGE_H