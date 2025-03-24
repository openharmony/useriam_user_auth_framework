/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include <cstdio>
#include "parcel.h"
#include "securec.h"

#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "user_idm_service.h"
#include "user_idm_callback_proxy.h"
#include "dummy_iam_callback_interface.h"

#undef private

using namespace std;
using namespace OHOS::UserIam::Common;

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
const int CMD_LEN = 19;
std::u16string cmd[] = {u"-h", u"-lc", u"-ls", u"-c", u"-c [base system]", u"-s", u"-s [SA0 SA1]", u"-s [SA] -a [-h]",
    u"-e", u"--net", u"--storage", u"-p", u"-p [pid]", u"--cpuusage [pid]", u"cified pid", u"--cpufreq", u"--mem [pid]",
    u"--zip", u"--mem-smaps pid [-v]"};

class DummyIdmGetCredentialInfoCallback : public IdmGetCredInfoCallbackInterface {
public:
    void OnCredentialInfos(int32_t result, const std::vector<CredentialInfo> &credInfoList) override
    {
        IAM_LOGI("start");
        return;
    }

    sptr<IRemoteObject> AsObject() override
    {
        sptr<IRemoteObject> tmp(nullptr);
        return tmp;
    }
};

class DummyIdmGetSecureUserInfoCallback : public IdmGetSecureUserInfoCallbackInterface {
public:
    void OnSecureUserInfo(int32_t result, const SecUserInfo &secUserInfo) override
    {
        IAM_LOGI("start");
        return;
    }

    sptr<IRemoteObject> AsObject() override
    {
        sptr<IRemoteObject> tmp(nullptr);
        return tmp;
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
        sptr<IRemoteObject> tmp(nullptr);
        return tmp;
    }
};

class DummyCredChangeListener : public EventListenerInterface {
public:
    ~DummyCredChangeListener() override = default;

    sptr<IRemoteObject> AsObject() override
    {
        sptr<IRemoteObject> tmp(nullptr);
        return tmp;
    }

    void OnNotifyAuthSuccessEvent(int32_t userId, AuthType authType, int32_t callerType,
        std::string &callerName) override
    {
        IAM_LOGI("notify: userId: %{public}d, authType: %{public}d, callerName: %{public}s,"
            "callerType: %{public}d", userId, static_cast<int32_t>(authType), callerName.c_str(), callerType);
    }
    void OnNotifyCredChangeEvent(int32_t userId, AuthType authType, CredChangeEventType eventType,
        uint64_t credentialId) override {}
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
    sptr<IdmGetCredInfoCallbackInterface> tmp(nullptr);
    if (parcel.ReadBool()) {
        tmp = sptr<IdmGetCredInfoCallbackInterface>(new (std::nothrow) DummyIdmGetCredentialInfoCallback());
    }
    return tmp;
}

sptr<IdmGetSecureUserInfoCallbackInterface> GetFuzzIdmGetSecureUserInfoCallback(Parcel &parcel)
{
    sptr<IdmGetSecureUserInfoCallbackInterface> tmp(nullptr);
    if (parcel.ReadBool()) {
        tmp = sptr<IdmGetSecureUserInfoCallbackInterface>(new (std::nothrow) DummyIdmGetSecureUserInfoCallback());
    }
    return tmp;
}

sptr<IdmCallbackInterface> GetFuzzIdmCallback(Parcel &parcel)
{
    sptr<IdmCallbackInterface> tmp(nullptr);
    if (parcel.ReadBool()) {
        tmp = sptr<IdmCallbackInterface>(new (std::nothrow) DummyIdmCallback());
    }
    return tmp;
}

UserIdmService g_UserIdmService(SUBSYS_USERIAM_SYS_ABILITY_USERIDM, true);

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

void FuzzDump(Parcel &parcel)
{
    IAM_LOGI("FuzzDump begin");
    std::vector<uint8_t> msg;
    Common::FillFuzzUint8Vector(parcel, msg);
    int32_t fd = parcel.ReadInt32();
    std::string fileName = to_string(fd) + ".txt";
    FILE *file = fopen(fileName.c_str(), "w");
    if (file != nullptr) {
        fd = fileno(file);
        std::vector<std::u16string> args;
        for (uint32_t i = 0; i < msg.size(); i++) {
            args.push_back(cmd[msg[i] % CMD_LEN]);
        }
        g_UserIdmService.Dump(fd, args);
        fclose(file);
        remove(fileName.c_str());
    }
    IAM_LOGI("FuzzDump end");
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

void FuzzClearRedundancyCredential(Parcel &parcel)
{
    IAM_LOGI("begin");
    sptr<IdmCallbackInterface> callback = GetFuzzIdmCallback(parcel);
    g_UserIdmService.ClearRedundancyCredential(callback);
    IAM_LOGI("end");
}

void FuzzClearRedundancyCredentialInner(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::string callerName = parcel.ReadString();
    int32_t callerType = parcel.ReadInt32();
    g_UserIdmService.ClearRedundancyCredentialInner(callerName, callerType);
    IAM_LOGI("end");
}

void FuzzEnforceDelUserInner(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = 100;
    sptr<IamCallbackInterface> iamCallback = sptr<IamCallbackInterface>(new (nothrow) DummyIamCallbackInterface);
    std::shared_ptr<ContextCallback> callbackForTrace =
        ContextCallback::NewInstance(iamCallback, TRACE_ENFORCE_DELETE_USER);
    std::string changeReasonTrace = parcel.ReadString();
    g_UserIdmService.EnforceDelUserInner(userId, callbackForTrace, changeReasonTrace);
    IAM_LOGI("end");
}

void FuzzCancelCurrentEnroll(Parcel &parcel)
{
    IAM_LOGI("begin");
    g_UserIdmService.CancelCurrentEnroll();
    g_UserIdmService.CancelCurrentEnrollIfExist();
    IAM_LOGI("end");
}

void FuzzStartEnroll(Parcel &parcel)
{
    IAM_LOGI("begin");
    Enrollment::EnrollmentPara para = {};
    sptr<IamCallbackInterface> iamCallback = sptr<IamCallbackInterface>(new (nothrow) DummyIamCallbackInterface);
    std::shared_ptr<ContextCallback> contextCallback = ContextCallback::NewInstance(iamCallback, TRACE_ADD_CREDENTIAL);
    Attributes extraInfo;
    g_UserIdmService.StartEnroll(para, contextCallback, extraInfo, true);
    IAM_LOGI("end");
}

void FuzzRegistCredChangeEventListener(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::vector<int32_t> authType;
    std::vector<AuthType> authTypeList;
    parcel.ReadInt32Vector(&authType);
    for (const auto &iter : authType) {
        authTypeList.push_back(static_cast<AuthType>(iter));
    }

    sptr<EventListenerInterface> callback(nullptr);
    if (parcel.ReadBool()) {
        callback = sptr<EventListenerInterface>(new (std::nothrow) DummyCredChangeEventListener());
    }

    g_UserIdmService.RegistCredChangeEventListener(authTypeList, callback);
    g_UserIdmService.UnRegistCredChangeEventListener(callback);
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzOpenSession);
FuzzFunc *g_fuzzFuncs[] = {
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
    FuzzDump,
    FuzzClearRedundancyCredential,
    FuzzClearRedundancyCredentialInner,
    FuzzEnforceDelUserInner,
    FuzzCancelCurrentEnroll,
    FuzzStartEnroll,
    FuzzRegistCredChangeEventListener,
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
