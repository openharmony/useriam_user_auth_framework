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
#ifndef IAM_MOCK_USER_IDM_CALLBACK_H
#define IAM_MOCK_USER_IDM_CALLBACK_H

#include <memory>

#include <gmock/gmock.h>
#include <iremote_stub.h>

#include "iiam_callback.h"
#include "iidm_get_cred_info_callback.h"
#include "iidm_get_secure_user_info_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockIdmGetCredentialInfoCallback final : public IRemoteStub<IIdmGetCredInfoCallback> {
public:
    MOCK_METHOD2(OnCredentialInfos, int32_t(int32_t result, const std::vector<IpcCredentialInfo> &credInfoList));
    MOCK_METHOD4(OnRemoteRequest,
        int32_t(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option));
    MOCK_METHOD1(CallbackEnter, int32_t(uint32_t code));
    MOCK_METHOD2(CallbackExit, int32_t(uint32_t code, int32_t result));
};

class MockIdmGetSecureUserInfoCallback final : public IRemoteStub<IIdmGetSecureUserInfoCallback> {
public:
    MOCK_METHOD2(OnSecureUserInfo, int32_t(int32_t resultCodeCode, const IpcSecUserInfo &secUserInfo));
    MOCK_METHOD4(OnRemoteRequest,
        int32_t(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option));
    MOCK_METHOD1(CallbackEnter, int32_t(uint32_t code));
    MOCK_METHOD2(CallbackExit, int32_t(uint32_t code, int32_t result));
};

class MockIdmCallback final : public IRemoteStub<IIamCallback> {
public:
    MOCK_METHOD2(OnResult, int32_t(int32_t resultCode, const std::vector<uint8_t> &extraInfo));
    MOCK_METHOD3(OnAcquireInfo, int32_t(int32_t module, int32_t acquire, const std::vector<uint8_t> &extraInfo));
    MOCK_METHOD4(OnRemoteRequest,
        int32_t(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option));
    MOCK_METHOD1(CallbackEnter, int32_t(uint32_t code));
    MOCK_METHOD2(CallbackExit, int32_t(uint32_t code, int32_t result));
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_MOCK_USER_IDM_CALLBACK_H