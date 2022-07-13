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

#include "user_auth_service_fuzzer.h"

#include <cinttypes>
#include <cstddef>
#include <cstdint>

#include "parcel.h"

#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "user_auth_service.h"

#undef private

#ifdef LOG_LABEL
#undef LOG_LABEL
#endif
#define LOG_LABEL OHOS::UserIAM::Common::LABEL_USER_AUTH_SA

using namespace std;
using namespace OHOS::UserIAM::Common;
using namespace OHOS::UserIam::UserAuth;

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
class DummyUserAuthCallback : public UserAuthCallbackInterface {
public:
    ~DummyUserAuthCallback() override = default;

    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, int32_t extraInfo) override
    {
        IAM_LOGI("start");
        return;
    }

    void OnAuthResult(int32_t result, const Attributes &extraInfo) override
    {
        IAM_LOGI("start");
        return;
    }

    void OnIdentifyResult(int32_t result, const Attributes &extraInfo) override
    {
        IAM_LOGI("start");
        return;
    }

    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }
};

class DummyGetExecutorPropertyCallback : public GetExecutorPropertyCallbackInterface {
public:
    ~DummyGetExecutorPropertyCallback() override = default;

    void OnGetExecutorPropertyResult(int32_t result, const Attributes &attributes) override
    {
        IAM_LOGI("start");
        return;
    }

    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }
};

class DummySetExecutorPropertyCallback : public SetExecutorPropertyCallbackInterface {
public:
    ~DummySetExecutorPropertyCallback() override = default;

    void OnSetExecutorPropertyResult(int32_t result) override
    {
        IAM_LOGI("start");
        return;
    }

    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }
};

std::optional<int32_t> GetFuzzOptionalUserId(Parcel &parcel)
{
    if (parcel.ReadBool()) {
        return parcel.ReadInt32();
    }
    return std::nullopt;
}

UserAuthService g_userAuthService(SUBSYS_USERIAM_SYS_ABILITY_USERAUTH, true);

void FuzzOnStart(Parcel &parcel)
{
    IAM_LOGI("begin");
    g_userAuthService.OnStart();
    IAM_LOGI("end");
}

void FuzzOnStop(Parcel &parcel)
{
    IAM_LOGI("begin");
    g_userAuthService.OnStop();
    IAM_LOGI("end");
}

void FuzzGetAvailableStatus(Parcel &parcel)
{
    IAM_LOGI("begin");
    AuthType authType = static_cast<AuthType>(parcel.ReadInt32());
    AuthTrustLevel authTrustLevel = static_cast<AuthTrustLevel>(parcel.ReadInt32());
    g_userAuthService.GetAvailableStatus(authType, authTrustLevel);
    IAM_LOGI("end");
}

void FuzzGetProperty(Parcel &parcel)
{
    IAM_LOGI("begin");
    constexpr uint32_t maxDataLen = 50;
    std::optional<int32_t> userId = GetFuzzOptionalUserId(parcel);
    AuthType authType = static_cast<AuthType>(parcel.ReadInt32());
    std::vector<Attributes::AttributeKey> keys;
    uint32_t keysLen = parcel.ReadUint32() % maxDataLen;
    keys.reserve(keysLen);
    for (uint32_t i = 0; i < keysLen; i++) {
        keys.emplace_back(static_cast<Attributes::AttributeKey>(parcel.ReadInt32()));
    }

    sptr<GetExecutorPropertyCallbackInterface> callback = nullptr;
    if (parcel.ReadBool()) {
        callback = new (nothrow) DummyGetExecutorPropertyCallback();
    }
    g_userAuthService.GetProperty(userId, authType, keys, callback);
    IAM_LOGI("end");
}

void FuzzSetProperty(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::optional<int32_t> userId = GetFuzzOptionalUserId(parcel);
    AuthType authType = static_cast<AuthType>(parcel.ReadInt32());
    vector<uint8_t> attributesRaw;
    FillFuzzUint8Vector(parcel, attributesRaw);
    Attributes attributes(attributesRaw);
    sptr<SetExecutorPropertyCallbackInterface> callback = nullptr;
    if (parcel.ReadBool()) {
        callback = new (nothrow) DummySetExecutorPropertyCallback();
    }

    g_userAuthService.SetProperty(userId, authType, attributes, callback);
    IAM_LOGI("end");
}

void FuzzAuthUser(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::optional<int32_t> userId = GetFuzzOptionalUserId(parcel);
    std::vector<uint8_t> challenge;
    FillFuzzUint8Vector(parcel, challenge);
    AuthType authType = static_cast<AuthType>(parcel.ReadInt32());
    AuthTrustLevel authTrustLevel = static_cast<AuthTrustLevel>(parcel.ReadInt32());
    sptr<UserAuthCallbackInterface> callback = nullptr;
    if (parcel.ReadBool()) {
        callback = new (nothrow) DummyUserAuthCallback();
    }
    g_userAuthService.AuthUser(userId, challenge, authType, authTrustLevel, callback);
    IAM_LOGI("end");
}

void FuzzIdentify(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::vector<uint8_t> challenge;
    FillFuzzUint8Vector(parcel, challenge);
    AuthType authType = static_cast<AuthType>(parcel.ReadInt32());
    sptr<UserAuthCallbackInterface> callback = nullptr;
    if (parcel.ReadBool()) {
        callback = new (nothrow) DummyUserAuthCallback();
    }
    g_userAuthService.Identify(challenge, authType, callback);
    IAM_LOGI("end");
}

void FuzzCancelAuthOrIdentify(Parcel &parcel)
{
    IAM_LOGI("begin");
    uint64_t contextId = parcel.ReadUint64();
    g_userAuthService.CancelAuthOrIdentify(contextId);
    IAM_LOGI("end");
}

void FuzzGetVersion(Parcel &parcel)
{
    IAM_LOGI("begin");
    g_userAuthService.GetVersion();
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzOnStart);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzOnStart,
    FuzzOnStop,
    FuzzGetAvailableStatus,
    FuzzGetProperty,
    FuzzSetProperty,
    FuzzAuthUser,
    FuzzIdentify,
    FuzzCancelAuthOrIdentify,
    FuzzGetVersion,
};

void UserAuthFuzzTest(const uint8_t *data, size_t size)
{
    Parcel parcel;
    parcel.WriteBuffer(data, size);
    parcel.RewindRead(0);
    uint32_t index = parcel.ReadUint32() % (sizeof(g_fuzzFuncs)) / sizeof(FuzzFunc *);
    auto fuzzFunc = g_fuzzFuncs[index];
    fuzzFunc(parcel);
    return;
}
} // namespace
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::UserIam::UserAuth::UserAuthFuzzTest(data, size);
    return 0;
}
