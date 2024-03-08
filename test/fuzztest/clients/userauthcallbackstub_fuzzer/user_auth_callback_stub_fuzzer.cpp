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

#include "user_auth_callback_stub_fuzzer.h"

#include "parcel.h"

#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "user_auth_callback_service.h"

#define LOG_TAG "USER_AUTH_SDK"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
constexpr uint32_t USER_AUTH_CALLBACK_CODE_MIN = 7;
constexpr uint32_t USER_AUTH_CALLBACK_CODE_MAX = 11;
const std::u16string USER_AUTH_CALLBACK_INTERFACE_TOKEN = u"ohos.UserIam.UserAuth.UserAuthCallback";
constexpr uint32_t GET_PROPERTY_CALLBACK_CODE_MIN = 8;
constexpr uint32_t GET_PROPERTY_CALLBACK_CODE_MAX = 9;
const std::u16string GET_PROPERTY_CALLBACK_INTERFACE_TOKEN = u"ohos.UserIam.UserAuth.GetExecutorPropertyCallback";
constexpr uint32_t SET_PROPERTY_CALLBACK_CODE_MIN = 9;
constexpr uint32_t SET_PROPERTY_CALLBACK_CODE_MAX = 10;
const std::u16string SET_PROPERTY_CALLBACK_INTERFACE_TOKEN = u"ohos.UserIam.UserAuth.SetExecutorPropertyCallback";

class DummyGetPropCallback final : public GetPropCallback {
public:
    void OnResult(int32_t result, const Attributes &extraInfo)
    {
        IAM_LOGI("start");
        static_cast<void>(result);
        static_cast<void>(extraInfo);
    }
};

class DummySetPropCallback final : public SetPropCallback {
public:
    void OnResult(int32_t result, const Attributes &extraInfo)
    {
        IAM_LOGI("start");
        static_cast<void>(result);
        static_cast<void>(extraInfo);
    }
};

class DummyAuthenticationCallback final : public AuthenticationCallback {
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

class DummyIdentificationCallback final : public IdentificationCallback {
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

auto g_UserAuthCallbackService =
    Common::MakeShared<UserAuthCallbackService>(Common::MakeShared<DummyAuthenticationCallback>());

auto g_GetPropCallbackService =
    Common::MakeShared<GetExecutorPropertyCallbackService>(Common::MakeShared<DummyGetPropCallback>());

auto g_SetPropCallbackService =
    Common::MakeShared<SetExecutorPropertyCallbackService>(Common::MakeShared<DummySetPropCallback>());

bool SetPropCallbackStubFuzzTest(const uint8_t *rawData, size_t size)
{
    IAM_LOGI("start");
    if (rawData == nullptr) {
        return false;
    }

    for (uint32_t code = SET_PROPERTY_CALLBACK_CODE_MIN; code < SET_PROPERTY_CALLBACK_CODE_MAX; code++) {
        MessageParcel data;
        MessageParcel reply;
        MessageOption optionSync = MessageOption::TF_SYNC;
        MessageOption optionAsync = MessageOption::TF_ASYNC;
        // Sync
        data.WriteInterfaceToken(SET_PROPERTY_CALLBACK_INTERFACE_TOKEN);
        data.WriteBuffer(rawData, size);
        data.RewindRead(0);
        (void)g_SetPropCallbackService->OnRemoteRequest(code, data, reply, optionSync);
        // Async
        data.WriteInterfaceToken(SET_PROPERTY_CALLBACK_INTERFACE_TOKEN);
        data.WriteBuffer(rawData, size);
        data.RewindRead(0);
        (void)g_SetPropCallbackService->OnRemoteRequest(code, data, reply, optionAsync);
    }
    return true;
}

bool GetPropCallbackStubFuzzTest(const uint8_t *rawData, size_t size)
{
    IAM_LOGI("start");
    if (rawData == nullptr) {
        return false;
    }

    for (uint32_t code = GET_PROPERTY_CALLBACK_CODE_MIN; code < GET_PROPERTY_CALLBACK_CODE_MAX; code++) {
        MessageParcel data;
        MessageParcel reply;
        MessageOption optionSync = MessageOption::TF_SYNC;
        MessageOption optionAsync = MessageOption::TF_ASYNC;
        // Sync
        data.WriteInterfaceToken(GET_PROPERTY_CALLBACK_INTERFACE_TOKEN);
        data.WriteBuffer(rawData, size);
        data.RewindRead(0);
        (void)g_GetPropCallbackService->OnRemoteRequest(code, data, reply, optionSync);
        // Async
        data.WriteInterfaceToken(GET_PROPERTY_CALLBACK_INTERFACE_TOKEN);
        data.WriteBuffer(rawData, size);
        data.RewindRead(0);
        (void)g_GetPropCallbackService->OnRemoteRequest(code, data, reply, optionAsync);
    }
    return true;
}

bool UserAuthCallbackStubFuzzTest(const uint8_t *rawData, size_t size)
{
    IAM_LOGI("start");
    if (rawData == nullptr) {
        return false;
    }

    for (uint32_t code = USER_AUTH_CALLBACK_CODE_MIN; code < USER_AUTH_CALLBACK_CODE_MAX; code++) {
        MessageParcel data;
        MessageParcel reply;
        MessageOption optionSync = MessageOption::TF_SYNC;
        MessageOption optionAsync = MessageOption::TF_ASYNC;
        // Sync
        data.WriteInterfaceToken(USER_AUTH_CALLBACK_INTERFACE_TOKEN);
        data.WriteBuffer(rawData, size);
        data.RewindRead(0);
        (void)g_UserAuthCallbackService->OnRemoteRequest(code, data, reply, optionSync);
        // Async
        data.WriteInterfaceToken(USER_AUTH_CALLBACK_INTERFACE_TOKEN);
        data.WriteBuffer(rawData, size);
        data.RewindRead(0);
        (void)g_UserAuthCallbackService->OnRemoteRequest(code, data, reply, optionAsync);
    }
    return true;
}
} // namespace
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::UserIam::UserAuth::UserAuthCallbackStubFuzzTest(data, size);
    OHOS::UserIam::UserAuth::GetPropCallbackStubFuzzTest(data, size);
    OHOS::UserIam::UserAuth::SetPropCallbackStubFuzzTest(data, size);
    return 0;
}
