/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "user_idm_client_stub_fuzzer.h"

#include "parcel.h"

#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "user_idm_client.h"
#include "user_idm_callback_service.h"

#define LOG_TAG "USER_AUTH_SDK"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
constexpr uint32_t IDM_CALLBACK_CODE_MIN = 0;
constexpr uint32_t IDM_CALLBACK_CODE_MAX = 2;
const std::u16string IDM_CALLBACK_INTERFACE_TOKEN = u"ohos.useridm.IIDMCallback";
constexpr uint32_t GET_CREDINFO_CALLBACK_CODE_MIN = 0;
constexpr uint32_t GET_CREDINFO_CALLBACK_CODE_MAX = 1;
const std::u16string GET_CREDINFO_CALLBACK_TOKEN = u"ohos.useridm.IGetInfoCallback";
constexpr uint32_t GET_SECURE_USERINFO_CALLBACK_CODE_MIN = 0;
constexpr uint32_t GET_SECURE_USERINFO_CALLBACK_CODE_MAX = 1;
const std::u16string GET_SECURE_USERINFO_CALLBACK_TOKEN = u"ohos.useridm.IGetSecInfoCallback";
class DummyUserIdmClientCallback final : public UserIdmClientCallback {
public:
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo)
    {
        IAM_LOGI("start");
        static_cast<void>(module);
        static_cast<void>(acquireInfo);
        static_cast<void>(extraInfo);
    }

    void OnResult(int32_t result, const Attributes &extraInfo)
    {
        IAM_LOGI("start");
        static_cast<void>(result);
        static_cast<void>(extraInfo);
    }
};

class DummyGetCredentialInfoCallback final : public GetCredentialInfoCallback {
public:
    void OnCredentialInfo(const std::vector<CredentialInfo> &infoList)
    {
        IAM_LOGI("start");
        static_cast<void>(infoList);
    }
};

class DummyGetSecUserInfoCallback final : public GetSecUserInfoCallback {
public:
    void OnSecUserInfo(const SecUserInfo &info)
    {
        IAM_LOGI("start");
        static_cast<void>(info);
    }
};

bool FuzzIdmCallbackStub(const uint8_t *rawData, size_t size)
{
    IAM_LOGI("start");
    if (rawData == nullptr) {
        IAM_LOGI("%{public}s:rawData is null.", __func__);
        return false;
    }
    auto idmCallbackService =
        Common::MakeShared<IdmCallbackService>(Common::MakeShared<DummyUserIdmClientCallback>());
    if (idmCallbackService == nullptr) {
        IAM_LOGI("%{public}s:new idmCallbackService failed.", __func__);
        return false;
    }
    for (uint32_t code = IDM_CALLBACK_CODE_MIN; code < IDM_CALLBACK_CODE_MAX; code++) {
        MessageParcel data;
        MessageParcel reply;
        MessageOption optionSync = MessageOption::TF_SYNC;
        MessageOption optionAsync = MessageOption::TF_ASYNC;
        // Sync
        data.WriteInterfaceToken(IDM_CALLBACK_INTERFACE_TOKEN);
        data.WriteBuffer(rawData, size);
        data.RewindRead(0);
        (void)idmCallbackService->OnRemoteRequest(code, data, reply, optionSync);
        // Async
        data.WriteInterfaceToken(IDM_CALLBACK_INTERFACE_TOKEN);
        data.WriteBuffer(rawData, size);
        data.RewindRead(0);
        (void)idmCallbackService->OnRemoteRequest(code, data, reply, optionAsync);
    }
    return true;
}

bool FuzzIdmGetInfoCallbackStub(const uint8_t *rawData, size_t size)
{
    IAM_LOGI("start");
    if (rawData == nullptr) {
        IAM_LOGI("%{public}s:rawData is null.", __func__);
        return false;
    }
    auto idmGetCredInfoCallbackService =
        Common::MakeShared<IdmGetCredInfoCallbackService>(Common::MakeShared<DummyGetCredentialInfoCallback>());
    if (idmGetCredInfoCallbackService == nullptr) {
        IAM_LOGI("%{public}s:new idmGetCredInfoCallbackService failed.", __func__);
        return false;
    }
    for (uint32_t code = GET_CREDINFO_CALLBACK_CODE_MIN; code < GET_CREDINFO_CALLBACK_CODE_MAX; code++) {
        MessageParcel data;
        MessageParcel reply;
        MessageOption optionSync = MessageOption::TF_SYNC;
        MessageOption optionAsync = MessageOption::TF_ASYNC;
        // Sync
        data.WriteInterfaceToken(GET_CREDINFO_CALLBACK_TOKEN);
        data.WriteBuffer(rawData, size);
        data.RewindRead(0);
        (void)idmGetCredInfoCallbackService->OnRemoteRequest(code, data, reply, optionSync);
        // Async
        data.WriteInterfaceToken(GET_CREDINFO_CALLBACK_TOKEN);
        data.WriteBuffer(rawData, size);
        data.RewindRead(0);
        (void)idmGetCredInfoCallbackService->OnRemoteRequest(code, data, reply, optionAsync);
    }
    return true;
}

bool FuzzIdmGetSecureUserInfoCallbackstub(const uint8_t *rawData, size_t size)
{
    IAM_LOGI("start");
    if (rawData == nullptr) {
        IAM_LOGI("%{public}s:rawData is null.", __func__);
        return false;
    }
    auto idmGetSecureUserInfoCallbackService =
        Common::MakeShared<IdmGetSecureUserInfoCallbackService>(Common::MakeShared<DummyGetSecUserInfoCallback>());
    if (idmGetSecureUserInfoCallbackService == nullptr) {
        IAM_LOGI("%{public}s:new idmGetSecureUserInfoCallbackService failed.", __func__);
        return false;
    }
    for (uint32_t code = GET_SECURE_USERINFO_CALLBACK_CODE_MIN; code < GET_SECURE_USERINFO_CALLBACK_CODE_MAX; code++) {
        MessageParcel data;
        MessageParcel reply;
        MessageOption optionSync = MessageOption::TF_SYNC;
        MessageOption optionAsync = MessageOption::TF_ASYNC;
        // Sync
        data.WriteInterfaceToken(GET_SECURE_USERINFO_CALLBACK_TOKEN);
        data.WriteBuffer(rawData, size);
        data.RewindRead(0);
        (void)idmGetSecureUserInfoCallbackService->OnRemoteRequest(code, data, reply, optionSync);
        // Async
        data.WriteInterfaceToken(GET_SECURE_USERINFO_CALLBACK_TOKEN);
        data.WriteBuffer(rawData, size);
        data.RewindRead(0);
        (void)idmGetSecureUserInfoCallbackService->OnRemoteRequest(code, data, reply, optionAsync);
    }
    return true;
}

void UserIdmClientFuzzTest(const uint8_t *data, size_t size)
{
    FuzzIdmCallbackStub(data, size);
    FuzzIdmGetInfoCallbackStub(data, size);
    FuzzIdmGetSecureUserInfoCallbackstub(data, size);
    return;
}
} // namespace
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::UserIam::UserAuth::UserIdmClientFuzzTest(data, size);
    return 0;
}
