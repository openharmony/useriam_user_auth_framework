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

#include <cstddef>
#include <cstdint>
#include <cinttypes>

#include "parcel.h"
#include "securec.h"

#include "iam_fuzz_test.h"
#include "iuserauth_callback.h"
#include "userauth_hilog_wrapper.h"
#include "userauth_service.h"

#undef private

using namespace std;
using namespace OHOS::UserIAM::Common;

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
namespace {
class DummyIUserAuthCallback : public IRemoteStub<IUserAuthCallback> {
public:

    void onAcquireInfo(const int32_t module, const uint32_t acquireInfo, const int32_t extraInfo) override
    {
        USERAUTH_HILOGI(MODULE_SERVICE, "DummyIUserAuthCallback onAcquireInfo");
        return;
    }

    void onResult(const int32_t result, const AuthResult &extraInfo) override
    {
        USERAUTH_HILOGI(MODULE_SERVICE, "DummyIUserAuthCallback onResult");
        return;
    }

    void onExecutorPropertyInfo(const ExecutorProperty &result) override
    {
        USERAUTH_HILOGI(MODULE_SERVICE, "DummyIUserAuthCallback onExecutorPropertyInfo");
        return;
    }

    void onSetExecutorProperty(const int32_t result) override
    {
        USERAUTH_HILOGI(MODULE_SERVICE, "DummyIUserAuthCallback onSetExecutorProperty");
        return;
    }

    virtual ~DummyIUserAuthCallback() = default;
};

UserAuthService g_userAuthService(SUBSYS_USERIAM_SYS_ABILITY_USERAUTH, true);

void FillFuzzTypeCallback(Parcel &parcel, sptr<IUserAuthCallback> &callbackObj)
{
    bool isNull = parcel.ReadBool();
    if (isNull) {
        callbackObj = nullptr;
    } else {
        callbackObj = new (std::nothrow) DummyIUserAuthCallback;
        if (callbackObj == nullptr) {
            USERAUTH_HILOGE(MODULE_SERVICE, "callbackObj construct fail");
        }
    }
    USERAUTH_HILOGI(MODULE_SERVICE, "success");
}

void FillFuzzGetPropertyRequest(Parcel &parcel, GetPropertyRequest &request)
{
    request.authType = static_cast<AuthType>(parcel.ReadUint32());
    FillFuzzUint32Vector(parcel, request.keys);
    USERAUTH_HILOGI(MODULE_SERVICE, "success");
}

void FillFuzzSetPropertyRequest(Parcel &parcel, SetPropertyRequest &request)
{
    request.authType = static_cast<AuthType>(parcel.ReadUint32());
    request.key = static_cast<SetPropertyType>(parcel.ReadUint32());
    FillFuzzUint8Vector(parcel, request.setInfo);
    USERAUTH_HILOGI(MODULE_SERVICE, "success");
}

void FuzzOnStart(Parcel &parcel)
{
    USERAUTH_HILOGI(MODULE_SERVICE, "begin");
    static_cast<void>(parcel);
    g_userAuthService.OnStart();
    USERAUTH_HILOGI(MODULE_SERVICE, "end");
}

void FuzzOnStop(Parcel &parcel)
{
    USERAUTH_HILOGI(MODULE_SERVICE, "begin");
    static_cast<void>(parcel);
    g_userAuthService.OnStop();
    USERAUTH_HILOGI(MODULE_SERVICE, "end");
}

void FuzzGetAvailableStatus(Parcel &parcel)
{
    USERAUTH_HILOGI(MODULE_SERVICE, "begin");
    AuthType authType = static_cast<AuthType>(parcel.ReadUint32());
    AuthTrustLevel authTrustLevel = static_cast<AuthTrustLevel>(parcel.ReadUint32());
    g_userAuthService.GetAvailableStatus(authType, authTrustLevel);
    USERAUTH_HILOGI(MODULE_SERVICE, "end");
}

void FuzzGetProperty(Parcel &parcel)
{
    USERAUTH_HILOGI(MODULE_SERVICE, "begin");
    GetPropertyRequest request;
    FillFuzzGetPropertyRequest(parcel, request);
    sptr<IUserAuthCallback> callback;
    FillFuzzTypeCallback(parcel, callback);
    g_userAuthService.GetProperty(request, callback);
    USERAUTH_HILOGI(MODULE_SERVICE, "end");
}

void FuzzSetProperty(Parcel &parcel)
{
    USERAUTH_HILOGI(MODULE_SERVICE, "begin");
    SetPropertyRequest request;
    FillFuzzSetPropertyRequest(parcel, request);
    sptr<IUserAuthCallback> callback;
    FillFuzzTypeCallback(parcel, callback);
    g_userAuthService.SetProperty(request, callback);
    USERAUTH_HILOGI(MODULE_SERVICE, "end");
}

void FuzzAuth(Parcel &parcel)
{
    USERAUTH_HILOGI(MODULE_SERVICE, "begin");
    int32_t userId =  parcel.ReadInt32();
    uint64_t challenge = parcel.ReadInt64();
    AuthType authType = static_cast<AuthType>(parcel.ReadUint32());
    AuthTrustLevel authTrustLevel = static_cast<AuthTrustLevel>(parcel.ReadUint32());
    sptr<IUserAuthCallback> callback;
    FillFuzzTypeCallback(parcel, callback);
    g_userAuthService.AuthUser(userId, challenge, authType, authTrustLevel, callback);
    USERAUTH_HILOGI(MODULE_SERVICE, "end");
}

void FuzzAuthUser(Parcel &parcel)
{
    USERAUTH_HILOGI(MODULE_SERVICE, "begin");
    int32_t userId = parcel.ReadInt32();
    uint64_t challenge = parcel.ReadInt64();
    AuthType authType = static_cast<AuthType>(parcel.ReadUint32());
    AuthTrustLevel authTrustLevel = static_cast<AuthTrustLevel>(parcel.ReadUint32());
    sptr<IUserAuthCallback> callback;
    FillFuzzTypeCallback(parcel, callback);
    g_userAuthService.AuthUser(userId, challenge, authType, authTrustLevel, callback);
    USERAUTH_HILOGI(MODULE_SERVICE, "end");
}

void FuzzCancelAuth(Parcel &parcel)
{
    USERAUTH_HILOGI(MODULE_SERVICE, "begin");
    uint64_t contextId = parcel.ReadInt64();
    g_userAuthService.CancelAuth(contextId);
    USERAUTH_HILOGI(MODULE_SERVICE, "end");
}

void FuzzGetVersion(Parcel &parcel)
{
    USERAUTH_HILOGI(MODULE_SERVICE, "begin");
    static_cast<void>(parcel);
    g_userAuthService.GetVersion();
    USERAUTH_HILOGI(MODULE_SERVICE, "end");
}

using FuzzFunc = decltype(FuzzAuth);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzOnStart,
    FuzzOnStop,
    FuzzGetAvailableStatus,
    FuzzGetProperty,
    FuzzSetProperty,
    FuzzAuth,
    FuzzAuthUser,
    FuzzCancelAuth,
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
} // namespace UserIAM
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::UserIAM::UserAuth::UserAuthFuzzTest(data, size);
    return 0;
}
