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

#ifndef MOCK_USER_IDM_CALLBACK_SERVICE_H
#define MOCK_USER_IDM_CALLBACK_SERVICE_H

#include <gmock/gmock.h>

#include "user_idm_callback_stub.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockIdmCallbackService final : public IdmCallbackStub {
public:
    MOCK_METHOD2(OnResult, void(int32_t result, const Attributes &extraInfo));
    MOCK_METHOD3(OnAcquireInfo, void(int32_t module, int32_t acquireInfo, const Attributes &extraInfo));
};

class MockIdmGetCredInfoCallbackService final : public IdmGetCredInfoCallbackStub {
public:
    MOCK_METHOD2(OnCredentialInfos, void(const std::vector<std::shared_ptr<CredentialInfo>> infoList,
        const std::optional<PinSubType> pinSubType));
};

class MockIdmGetSecureUserInfoCallbackService final : public IdmGetSecureUserInfoCallbackStub {
public:
    MOCK_METHOD1(OnSecureUserInfo, void(const std::shared_ptr<SecureUserInfo> info));
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // MOCK_USER_IDM_CALLBACK_SERVICE_H
