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

#include "user_idm_service_fuzzer.h"

#include "parcel.h"
#include "securec.h"

#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "user_idm_service.h"

#undef private

using namespace std;
using namespace OHOS::UserIam::Common;

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
class DummyIdmGetCredentialInfoCallback : public IdmGetCredInfoCallbackInterface {
public:
    void OnCredentialInfos(const std::vector<std::shared_ptr<CredentialInfo>> infoList,
        const std::optional<PinSubType> pinSubType) override
    {
        IAM_LOGI("start");
        return;
    }

    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }
};

class DummyIdmGetSecureUserInfoCallback : public IdmGetSecureUserInfoCallbackInterface {
public:
    void OnSecureUserInfo(const std::shared_ptr<SecureUserInfo> info) override
    {
        IAM_LOGI("start");
        return;
    }

    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }
};

class DummyIdmCallback : public IdmCallbackInterface {
public:
    void OnResult(int32_t result, const Attributes &reqRet) override
    {
        IAM_LOGI("start");
        return;
    }

    void OnAcquireInfo(int32_t module, int32_t acquire, const Attributes &reqRet) override
    {
        IAM_LOGI("start");
        return;
    }

    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }
};

int32_t GetFuzzOptionalUserId(Parcel &parcel)
{
    if (parcel.ReadBool()) {
        return parcel.ReadInt32();
    }
    return 0;
}

sptr<IdmGetCredInfoCallbackInterface> GetFuzzIdmGetCredentialInfoCallback(Parcel &parcel)
{
    if (parcel.ReadBool()) {
        return new (nothrow) DummyIdmGetCredentialInfoCallback();
    }
    return nullptr;
}

sptr<IdmGetSecureUserInfoCallbackInterface> GetFuzzIdmGetSecureUserInfoCallback(Parcel &parcel)
{
    if (parcel.ReadBool()) {
        return new (nothrow) DummyIdmGetSecureUserInfoCallback();
    }
    return nullptr;
}

sptr<IdmCallbackInterface> GetFuzzIdmCallback(Parcel &parcel)
{
    if (parcel.ReadBool()) {
        return new (nothrow) DummyIdmCallback();
    }
    return nullptr;
}

UserIdmService g_UserIdmService(SUBSYS_USERIAM_SYS_ABILITY_USERIDM, true);

void FuzzOnStart(Parcel &parcel)
{
    IAM_LOGI("begin");
    g_UserIdmService.OnStart();
    IAM_LOGI("end");
}

void FuzzOnStop(Parcel &parcel)
{
    IAM_LOGI("begin");
    static int32_t skipCount = 1000;
    // OnStop affects test of other function, skip it in the first phase
    if (skipCount > 0) {
        --skipCount;
        return;
    }
    g_UserIdmService.OnStop();
    IAM_LOGI("end");
}

void FuzzOpenSession(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = GetFuzzOptionalUserId(parcel);
    std::vector<uint8_t> challenge;
    FillFuzzUint8Vector(parcel, challenge);
    g_UserIdmService.OpenSession(userId, challenge);
    IAM_LOGI("end");
}

void FuzzCloseSession(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = GetFuzzOptionalUserId(parcel);
    g_UserIdmService.CloseSession(userId);
    IAM_LOGI("end");
}

void FuzzGetCredentialInfo(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = GetFuzzOptionalUserId(parcel);
    AuthType authType = static_cast<AuthType>(parcel.ReadUint32());
    sptr<IdmGetCredInfoCallbackInterface> callback = GetFuzzIdmGetCredentialInfoCallback(parcel);
    g_UserIdmService.GetCredentialInfo(userId, authType, callback);
    IAM_LOGI("end");
}

void FuzzGetSecInfo(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = GetFuzzOptionalUserId(parcel);
    sptr<IdmGetSecureUserInfoCallbackInterface> callback = GetFuzzIdmGetSecureUserInfoCallback(parcel);
    g_UserIdmService.GetSecInfo(userId, callback);
    IAM_LOGI("end");
}

void FuzzAddCredential(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    UserIdmInterface::CredentialPara para = {};
    para.authType = static_cast<AuthType>(parcel.ReadInt32());
    para.pinType = static_cast<PinSubType>(parcel.ReadInt32());
    FillFuzzUint8Vector(parcel, para.token);
    sptr<IdmCallbackInterface> callback = GetFuzzIdmCallback(parcel);
    g_UserIdmService.AddCredential(userId, para, callback, false);
    IAM_LOGI("end");
}

void FuzzUpdateCredential(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    UserIdmInterface::CredentialPara para = {};
    para.authType = static_cast<AuthType>(parcel.ReadInt32());
    para.pinType = static_cast<PinSubType>(parcel.ReadInt32());
    FillFuzzUint8Vector(parcel, para.token);
    sptr<IdmCallbackInterface> callback = GetFuzzIdmCallback(parcel);
    g_UserIdmService.UpdateCredential(userId, para, callback);
    IAM_LOGI("end");
}

void FuzzCancel(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    g_UserIdmService.Cancel(userId);
    IAM_LOGI("end");
}

void FuzzEnforceDelUser(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    sptr<IdmCallbackInterface> callback = GetFuzzIdmCallback(parcel);
    g_UserIdmService.EnforceDelUser(userId, callback);
    IAM_LOGI("end");
}

void FuzzDelUser(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    std::vector<uint8_t> authToken;
    FillFuzzUint8Vector(parcel, authToken);
    sptr<IdmCallbackInterface> callback = GetFuzzIdmCallback(parcel);
    g_UserIdmService.DelUser(userId, authToken, callback);
    IAM_LOGI("end");
}

void DelCredential(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    uint64_t credentialId = parcel.ReadUint64();
    std::vector<uint8_t> authToken;
    FillFuzzUint8Vector(parcel, authToken);
    sptr<IdmCallbackInterface> callback = GetFuzzIdmCallback(parcel);
    g_UserIdmService.DelCredential(userId, credentialId, authToken, callback);
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzOnStart);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzOnStart,
    FuzzOnStop,
    FuzzOpenSession,
    FuzzCloseSession,
    FuzzGetCredentialInfo,
    FuzzGetSecInfo,
    FuzzAddCredential,
    FuzzUpdateCredential,
    FuzzCancel,
    FuzzEnforceDelUser,
    FuzzDelUser,
    DelCredential,
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
} // namespace
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::UserIam::UserAuth::UserIdmFuzzTest(data, size);
    return 0;
}
