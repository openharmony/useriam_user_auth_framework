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

#include "user_idm_fuzzer.h"
#include "parcel.h"
#include "securec.h"
#include "iam_fuzz_test.h"
#include "useridm_service.h"
#include "useridm_hilog_wrapper.h"


#undef private

using namespace std;
using namespace OHOS::UserIAM::Common;

namespace OHOS {
namespace UserIAM {
namespace UserIDM {
namespace {
class GetInfoCallbackFuzzer : public IRemoteStub<IGetInfoCallback> {
public:
    virtual ~GetInfoCallbackFuzzer() = default;
    void OnGetInfo(std::vector<CredentialInfo> &info) override
    {
        USERIDM_HILOGI(MODULE_SERVICE, "GetInfoCallbackFuzzer OnGetInfo");
        return;
    }
};

class GetSecInfoCallbackFuzzer : public IRemoteStub<IGetSecInfoCallback> {
public:
    virtual ~GetSecInfoCallbackFuzzer() = default;
    void OnGetSecInfo(SecInfo &info) override
    {
        USERIDM_HILOGI(MODULE_SERVICE, "GetSecInfoCallbackFuzzer OnGetSecInfo");
        return;
    }
};

class IdmCallbackFuzzer : public IRemoteStub<IIDMCallback> {
public:
    virtual ~IdmCallbackFuzzer() = default;
    void OnResult(int32_t result, RequestResult reqRet) override
    {
        USERIDM_HILOGI(MODULE_SERVICE, "IdmCallbackFuzzer OnResult");
        return;
    }

    void OnAcquireInfo(int32_t module, int32_t acquire, RequestResult reqRet) override
    {
        USERIDM_HILOGI(MODULE_SERVICE, "IdmCallbackFuzzer OnAcquireInfo");
        return;
    }
};

void FillFuzzAddCredInfo(Parcel &parcel, AddCredInfo &credInfo)
{
    credInfo.authType = static_cast<AuthType>(parcel.ReadUint32());
    credInfo.authSubType = static_cast<AuthSubType>(parcel.ReadUint64());
    FillFuzzUint8Vector(parcel, credInfo.token);
    USERIDM_HILOGI(MODULE_SERVICE, "success");
}

UserIDMService g_userIdmService(SUBSYS_USERIAM_SYS_ABILITY_USERIDM, true);

void FuzzOnStart(Parcel &parcel)
{
    USERIDM_HILOGI(MODULE_SERVICE, "begin");
    static_cast<void>(parcel);
    g_userIdmService.OnStart();
    USERIDM_HILOGI(MODULE_SERVICE, "end");
}

void FuzzOnStop(Parcel &parcel)
{
    USERIDM_HILOGI(MODULE_SERVICE, "begin");
    static_cast<void>(parcel);
    g_userIdmService.OnStop();
    USERIDM_HILOGI(MODULE_SERVICE, "end");
}

void FuzzOpenSession(Parcel &parcel)
{
    USERIDM_HILOGI(MODULE_SERVICE, "begin");
    static_cast<void>(parcel);
    g_userIdmService.OpenSession();
    USERIDM_HILOGI(MODULE_SERVICE, "end");
}

void FuzzCloseSession(Parcel &parcel)
{
    USERIDM_HILOGI(MODULE_SERVICE, "begin");
    static_cast<void>(parcel);
    g_userIdmService.CloseSession();
    USERIDM_HILOGI(MODULE_SERVICE, "end");
}

void FuzzGetAuthInfo_a(Parcel &parcel)
{
    USERIDM_HILOGI(MODULE_SERVICE, "begin");
    AuthType authType = static_cast<AuthType>(parcel.ReadUint32());
    sptr<IGetInfoCallback> callback = nullptr;
    if (parcel.ReadBool()) {
        callback = new (std::nothrow) GetInfoCallbackFuzzer();
    }
    g_userIdmService.GetAuthInfo(authType, callback);
    USERIDM_HILOGI(MODULE_SERVICE, "end");
}

void FuzzGetAuthInfo_b(Parcel &parcel)
{
    USERIDM_HILOGI(MODULE_SERVICE, "begin");
    int32_t userId = parcel.ReadInt32();
    AuthType authType = static_cast<AuthType>(parcel.ReadUint32());
    sptr<IGetInfoCallback> callback = nullptr;
    if (parcel.ReadBool()) {
        callback = new (std::nothrow) GetInfoCallbackFuzzer();
    }
    g_userIdmService.GetAuthInfo(userId, authType, callback);
    USERIDM_HILOGI(MODULE_SERVICE, "end");
}

void FuzzGetSecInfo(Parcel &parcel)
{
    USERIDM_HILOGI(MODULE_SERVICE, "begin");
    int32_t userId = parcel.ReadInt32();
    sptr<IGetSecInfoCallback> callback = nullptr;
    if (parcel.ReadBool()) {
        callback = new (std::nothrow) GetSecInfoCallbackFuzzer();
    }
    g_userIdmService.GetSecInfo(userId, callback);
    USERIDM_HILOGI(MODULE_SERVICE, "end");
}

void FuzzAddCredential(Parcel &parcel)
{
    USERIDM_HILOGI(MODULE_SERVICE, "begin");
    AddCredInfo credInfo;
    FillFuzzAddCredInfo(parcel, credInfo);
    sptr<IIDMCallback> callback = nullptr;
    if (parcel.ReadBool()) {
        callback = new (std::nothrow) IdmCallbackFuzzer();
    }
    g_userIdmService.AddCredential(credInfo, callback);
    USERIDM_HILOGI(MODULE_SERVICE, "end");
}

void FuzzUpdateCredential(Parcel &parcel)
{
    USERIDM_HILOGI(MODULE_SERVICE, "begin");
    AddCredInfo credInfo;
    FillFuzzAddCredInfo(parcel, credInfo);
    sptr<IIDMCallback> callback = nullptr;
    if (parcel.ReadBool()) {
        callback = new (std::nothrow) IdmCallbackFuzzer();
    }
    g_userIdmService.UpdateCredential(credInfo, callback);
    USERIDM_HILOGI(MODULE_SERVICE, "end");
}

void FuzzCancel(Parcel &parcel)
{
    USERIDM_HILOGI(MODULE_SERVICE, "begin");
    uint64_t challenge = parcel.ReadUint64();
    g_userIdmService.Cancel(challenge);
    USERIDM_HILOGI(MODULE_SERVICE, "end");
}

void FuzzEnforceDelUser(Parcel &parcel)
{
    USERIDM_HILOGI(MODULE_SERVICE, "begin");
    uint32_t userId = parcel.ReadUint32();
    sptr<IIDMCallback> callback = nullptr;
    if (parcel.ReadBool()) {
        callback = new (std::nothrow) IdmCallbackFuzzer();
    }
    g_userIdmService.EnforceDelUser(userId, callback);
    USERIDM_HILOGI(MODULE_SERVICE, "end");
}

void FuzzDelUser(Parcel &parcel)
{
    USERIDM_HILOGI(MODULE_SERVICE, "begin");
    std::vector<uint8_t> authToken;
    FillFuzzUint8Vector(parcel, authToken);
    sptr<IIDMCallback> callback = nullptr;
    if (parcel.ReadBool()) {
        callback = new (std::nothrow) IdmCallbackFuzzer();
    }
    g_userIdmService.DelUser(authToken, callback);
    USERIDM_HILOGI(MODULE_SERVICE, "end");
}

void FuzzDelCred(Parcel &parcel)
{
    USERIDM_HILOGI(MODULE_SERVICE, "begin");
    uint64_t credentialId = parcel.ReadUint64();
    std::vector<uint8_t> authToken;
    FillFuzzUint8Vector(parcel, authToken);
    sptr<IIDMCallback> callback = nullptr;
    if (parcel.ReadBool()) {
        callback = new (std::nothrow) IdmCallbackFuzzer();
    }
    g_userIdmService.DelCred(credentialId, authToken, callback);
    USERIDM_HILOGI(MODULE_SERVICE, "end");
}

using FuzzFunc = decltype(FuzzDelCred);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzOnStart,
    FuzzOnStop,
    FuzzOpenSession,
    FuzzCloseSession,
    FuzzGetAuthInfo_a,
    FuzzGetAuthInfo_b,
    FuzzGetSecInfo,
    FuzzAddCredential,
    FuzzUpdateCredential,
    FuzzCancel,
    FuzzEnforceDelUser,
    FuzzDelUser,
    FuzzDelCred,
};

void UserIdmFuzzTest(const uint8_t *data, size_t size)
{
    Parcel parcel;
    parcel.WriteBuffer(data, size);
    parcel.RewindRead(0);
    uint32_t index = parcel.ReadUint32() % (sizeof(g_fuzzFuncs) / sizeof(FuzzFunc *));
    auto fuzzFunc = g_fuzzFuncs[index];
    fuzzFunc(parcel);
    return;
}
}
} // namespace UserIDM
} // namespace UserIAM
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::UserIAM::UserIDM::UserIdmFuzzTest(data, size);
    return 0;
}
