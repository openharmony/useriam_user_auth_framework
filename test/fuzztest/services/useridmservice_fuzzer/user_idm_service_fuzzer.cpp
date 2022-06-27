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
using namespace OHOS::UserIAM::Common;

#define LOG_LABEL OHOS::UserIAM::Common::LABEL_USER_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
class DummyIdmGetCredentialInfoCallback : public IdmGetCredentialInfoCallback {
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

class DummyIdmGetSecureUserInfoCallback : public IdmGetSecureUserInfoCallback {
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

class DummyIdmCallback : public IdmCallback {
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

std::optional<int32_t> GetFuzzOptionalUserId(Parcel &parcel)
{
    if (parcel.ReadBool()) {
        return parcel.ReadInt32();
    }
    return std::nullopt;
}

sptr<IdmGetCredentialInfoCallback> GetFuzzIdmGetCredentialInfoCallback(Parcel &parcel)
{
    if (parcel.ReadBool()) {
        return new (std::nothrow) DummyIdmGetCredentialInfoCallback();
    }
    return nullptr;
}

sptr<IdmGetSecureUserInfoCallback> GetFuzzIdmGetSecureUserInfoCallback(Parcel &parcel)
{
    if (parcel.ReadBool()) {
        return new (std::nothrow) DummyIdmGetSecureUserInfoCallback();
    }
    return nullptr;
}

sptr<IdmCallback> GetFuzzIdmCallback(Parcel &parcel)
{
    if (parcel.ReadBool()) {
        return new (std::nothrow) DummyIdmCallback();
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
    g_UserIdmService.OnStop();
    IAM_LOGI("end");
}

void FuzzOpenSession(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::optional<int32_t> userId = GetFuzzOptionalUserId(parcel);
    std::vector<uint8_t> challenge;
    FillFuzzUint8Vector(parcel, challenge);
    g_UserIdmService.OpenSession(userId, challenge);
    IAM_LOGI("end");
}

void FuzzCloseSession(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::optional<int32_t> userId = GetFuzzOptionalUserId(parcel);
    g_UserIdmService.CloseSession(userId);
    IAM_LOGI("end");
}

void FuzzGetCredentialInfo(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::optional<int32_t> userId = GetFuzzOptionalUserId(parcel);
    AuthType authType = static_cast<AuthType>(parcel.ReadUint32());
    sptr<IdmGetCredentialInfoCallback> callback = GetFuzzIdmGetCredentialInfoCallback(parcel);
    g_UserIdmService.GetCredentialInfo(userId, authType, callback);
    IAM_LOGI("end");
}

void FuzzGetSecInfo(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::optional<int32_t> userId = GetFuzzOptionalUserId(parcel);
    sptr<IdmGetSecureUserInfoCallback> callback = GetFuzzIdmGetSecureUserInfoCallback(parcel);
    g_UserIdmService.GetSecInfo(userId, callback);
    IAM_LOGI("end");
}

void FuzzAddCredential(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    AuthType authType = static_cast<AuthType>(parcel.ReadInt32());
    PinSubType pinSubType = static_cast<PinSubType>(parcel.ReadInt32());
    std::vector<uint8_t> token;
    FillFuzzUint8Vector(parcel, token);
    sptr<IdmCallback> callback = GetFuzzIdmCallback(parcel);
    g_UserIdmService.AddCredential(userId, authType, pinSubType, token, callback);
    IAM_LOGI("end");
}

void FuzzUpdateCredential(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    AuthType authType = static_cast<AuthType>(parcel.ReadInt32());
    PinSubType pinSubType = static_cast<PinSubType>(parcel.ReadInt32());
    std::vector<uint8_t> token;
    FillFuzzUint8Vector(parcel, token);
    sptr<IdmCallback> callback = GetFuzzIdmCallback(parcel);
    g_UserIdmService.UpdateCredential(userId, authType, pinSubType, token, callback);
    IAM_LOGI("end");
}

void FuzzCancel(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    std::vector<uint8_t> challenge;
    FillFuzzUint8Vector(parcel, challenge);
    g_UserIdmService.Cancel(userId, challenge);
    IAM_LOGI("end");
}

void FuzzEnforceDelUser(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    sptr<IdmCallback> callback = GetFuzzIdmCallback(parcel);
    g_UserIdmService.EnforceDelUser(userId, callback);
    IAM_LOGI("end");
}

void FuzzDelUser(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    std::vector<uint8_t> authToken;
    FillFuzzUint8Vector(parcel, authToken);
    sptr<IdmCallback> callback = GetFuzzIdmCallback(parcel);
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
    sptr<IdmCallback> callback = GetFuzzIdmCallback(parcel);
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
