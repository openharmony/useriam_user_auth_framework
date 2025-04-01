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

#include "iam_callback_stub.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockIdmCallbackService final : public IamCallbackStub {
public:
    MOCK_METHOD2(OnResult, int32_t(int32_t resultCode, const std::vector<uint8_t> &extraInfo));
    MOCK_METHOD3(OnAcquireInfo, int32_t(int32_t module, int32_t acquireInfo, const std::vector<uint8_t> &extraInfo));
    MOCK_METHOD1(CallbackEnter, int32_t(uint32_t code));
    MOCK_METHOD2(CallbackExit, int32_t(uint32_t code, int32_t result));
};

class MockIdmGetCredInfoCallbackService final : public IdmGetCredInfoCallbackStub {
public:
    MOCK_METHOD2(OnCredentialInfos, int32_t(int32_t result, const std::vector<IpcCredentialInfo> &credInfoList));
    MOCK_METHOD1(CallbackEnter, int32_t(uint32_t code));
    MOCK_METHOD2(CallbackExit, int32_t(uint32_t code, int32_t result));
};

class MockIdmGetSecureUserInfoCallbackService final : public IdmGetSecureUserInfoCallbackStub {
public:
    MOCK_METHOD2(OnSecureUserInfo, int32_t(int32_t resultCodeCode, const IpcSecUserInfo &secUserInfo));
    MOCK_METHOD1(CallbackEnter, int32_t(uint32_t code));
    MOCK_METHOD2(CallbackExit, int32_t(uint32_t code, int32_t result));
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // MOCK_USER_IDM_CALLBACK_SERVICE_H
