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

#include "user_auth_client_fuzzer.h"

#include "parcel.h"

#include "user_auth_client_impl.h"
#include "user_auth_callback_service.h"
#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_LABEL OHOS::UserIam::Common::LABEL_USER_AUTH_SDK

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
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

void FuzzClientGetAvailableStatus(Parcel &parcel)
{
    IAM_LOGI("start");
    auto authType = static_cast<AuthType>(parcel.ReadInt32());
    auto atl = static_cast<AuthTrustLevel>(parcel.ReadUint32());
    UserAuthClientImpl::Instance().GetAvailableStatus(authType, atl);
    IAM_LOGI("end");
}

void FuzzClientGetProperty(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t userId = parcel.ReadInt32();
    GetPropertyRequest request = {};
    request.authType = static_cast<AuthType>(parcel.ReadInt32());
    request.keys.push_back(static_cast<Attributes::AttributeKey>(parcel.ReadUint32()));
    auto callback = Common::MakeShared<DummyGetPropCallback>();
    UserAuthClient::GetInstance().GetProperty(userId, request, callback);
    IAM_LOGI("end");
}

void FuzzClientSetProperty(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t userId = parcel.ReadInt32();
    SetPropertyRequest request = {};
    request.authType = static_cast<AuthType>(parcel.ReadInt32());
    request.mode = static_cast<PropertyMode>(parcel.ReadUint32());
    auto callback = Common::MakeShared<DummySetPropCallback>();
    UserAuthClient::GetInstance().SetProperty(userId, request, callback);
    IAM_LOGI("end");
}

void FuzzClientBeginAuthentication001(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t userId = parcel.ReadInt32();
    std::vector<uint8_t> challenge;
    Common::FillFuzzUint8Vector(parcel, challenge);
    auto authType = static_cast<AuthType>(parcel.ReadInt32());
    auto atl = static_cast<AuthTrustLevel>(parcel.ReadUint32());
    auto callback = Common::MakeShared<DummyAuthenticationCallback>();
    UserAuthClient::GetInstance().BeginAuthentication(userId, challenge, authType, atl, callback);
    IAM_LOGI("end");
}

void FuzzClientBeginAuthentication002(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t apiVersion = parcel.ReadInt32();
    std::vector<uint8_t> challenge;
    Common::FillFuzzUint8Vector(parcel, challenge);
    auto authType = static_cast<AuthType>(parcel.ReadInt32());
    auto atl = static_cast<AuthTrustLevel>(parcel.ReadUint32());
    auto callback = Common::MakeShared<DummyAuthenticationCallback>();
    UserAuthClientImpl::Instance().BeginNorthAuthentication(apiVersion, challenge, authType, atl, callback);
    IAM_LOGI("end");
}

void FuzzClientCancelAuthentication(Parcel &parcel)
{
    IAM_LOGI("start");
    uint64_t contextId = parcel.ReadUint64();
    UserAuthClient::GetInstance().CancelAuthentication(contextId);
    IAM_LOGI("end");
}

void FuzzClientBeginIdentification(Parcel &parcel)
{
    IAM_LOGI("start");
    std::vector<uint8_t> challenge;
    Common::FillFuzzUint8Vector(parcel, challenge);
    auto authType = static_cast<AuthType>(parcel.ReadInt32());
    auto callback = Common::MakeShared<DummyIdentificationCallback>();
    UserAuthClient::GetInstance().BeginIdentification(challenge, authType, callback);
    IAM_LOGI("end");
}

void FuzzCancelIdentification(Parcel &parcel)
{
    IAM_LOGI("start");
    uint64_t contextId = parcel.ReadUint64();
    UserAuthClient::GetInstance().CancelIdentification(contextId);
    IAM_LOGI("end");
}

void FuzzClientGetVersion(Parcel &parcel)
{
    IAM_LOGI("start");
    static_cast<void>(parcel.ReadInt32());
    int32_t version = -1;
    UserAuthClientImpl::Instance().GetVersion(version);
    IAM_LOGI("end");
}

auto g_UserAuthCallbackService =
    Common::MakeShared<UserAuthCallbackService>(Common::MakeShared<DummyAuthenticationCallback>());

auto g_GetPropCallbackService =
    Common::MakeShared<GetExecutorPropertyCallbackService>(Common::MakeShared<DummyGetPropCallback>());

auto g_SetPropCallbackService =
    Common::MakeShared<SetExecutorPropertyCallbackService>(Common::MakeShared<DummySetPropCallback>());

void FuzzUserAuthCallbackServiceOnResult(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t result = parcel.ReadInt32();
    std::vector<uint8_t> attr;
    Common::FillFuzzUint8Vector(parcel, attr);
    Attributes extraInfo(attr);
    if (g_UserAuthCallbackService != nullptr) {
        g_UserAuthCallbackService->OnResult(result, extraInfo);
    }
    IAM_LOGI("end");
}

void FuzzUserAuthCallbackServiceOnAcquireInfo(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t result = parcel.ReadInt32();
    int32_t acquireInfo = parcel.ReadInt32();
    std::vector<uint8_t> attr;
    Common::FillFuzzUint8Vector(parcel, attr);
    Attributes extraInfo(attr);
    if (g_UserAuthCallbackService != nullptr) {
        g_UserAuthCallbackService->OnAcquireInfo(result, acquireInfo, extraInfo);
    }
    IAM_LOGI("end");
}

void FuzzGetPropCallbackServiceOnPropResult(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t result = parcel.ReadInt32();
    std::vector<uint8_t> attr;
    Common::FillFuzzUint8Vector(parcel, attr);
    Attributes extraInfo(attr);
    if (g_GetPropCallbackService != nullptr) {
        g_GetPropCallbackService->OnGetExecutorPropertyResult(result, extraInfo);
    }
    IAM_LOGI("end");
}

void FuzzSetPropCallbackServiceOnPropResult(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t result = parcel.ReadInt32();
    if (g_SetPropCallbackService != nullptr) {
        g_SetPropCallbackService->OnSetExecutorPropertyResult(result);
    }
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzClientGetAvailableStatus);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzClientGetAvailableStatus,
    FuzzClientGetProperty,
    FuzzClientSetProperty,
    FuzzClientBeginAuthentication001,
    FuzzClientBeginAuthentication002,
    FuzzClientCancelAuthentication,
    FuzzClientBeginIdentification,
    FuzzCancelIdentification,
    FuzzClientGetVersion,
    FuzzUserAuthCallbackServiceOnResult,
    FuzzUserAuthCallbackServiceOnAcquireInfo,
    FuzzGetPropCallbackServiceOnPropResult,
    FuzzSetPropCallbackServiceOnPropResult,
};

void UserAuthClientFuzzTest(const uint8_t *data, size_t size)
{
    Parcel parcel;
    parcel.WriteBuffer(data, size);
    parcel.RewindRead(0);
    uint32_t index = parcel.ReadUint32() % (sizeof(g_fuzzFuncs) / sizeof(FuzzFunc *));
    auto fuzzFunc = g_fuzzFuncs[index];
    fuzzFunc(parcel);
    return;
}
} // namespace
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::UserIam::UserAuth::UserAuthClientFuzzTest(data, size);
    return 0;
}
