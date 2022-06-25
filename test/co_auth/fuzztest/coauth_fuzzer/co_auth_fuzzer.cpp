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

#include "co_auth_fuzzer.h"
#include "coauth_service.h"
#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "parcel.h"
#include "securec.h"

#define LOG_LABEL OHOS::UserIAM::Common::LABEL_USER_AUTH_SA

#undef private

using namespace std;
using namespace OHOS::UserIAM::Common;
using namespace OHOS::UserIAM::AuthResPool;

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
namespace {
class ResIExecutorCallbackFuzzer : public IRemoteStub<ResIExecutorCallback> {
public:
    ResIExecutorCallbackFuzzer(int32_t onBeginExecuteResult, int32_t onEndExecuteResult, int32_t onSetPropertyResult,
        int32_t onGetPropertyResult)
        : onBeginExecuteResult_(onBeginExecuteResult),
          onEndExecuteResult_(onEndExecuteResult),
          onSetPropertyResult_(onSetPropertyResult),
          onGetPropertyResult_(onGetPropertyResult)
    {
    }

    virtual ~ResIExecutorCallbackFuzzer() = default;

    void OnMessengerReady(const sptr<IExecutorMessenger> &messenger, std::vector<uint8_t> &frameworkPublicKey,
        std::vector<uint64_t> &templateIds) override
    {
        IAM_LOGI("ResIExecutorCallbackFuzzer OnMessengerReady");
        return;
    }

    int32_t OnBeginExecute(
        uint64_t scheduleId, std::vector<uint8_t> &publicKey, std::shared_ptr<AuthAttributes> commandAttrs) override
    {
        IAM_LOGI("ResIExecutorCallbackFuzzer OnBeginExecute");
        return onBeginExecuteResult_;
    }

    int32_t OnEndExecute(uint64_t scheduleId, std::shared_ptr<AuthAttributes> consumerAttr) override
    {
        IAM_LOGI("ResIExecutorCallbackFuzzer OnEndExecute");
        return onEndExecuteResult_;
    }

    int32_t OnSetProperty(std::shared_ptr<AuthAttributes> properties) override
    {
        IAM_LOGI("ResIExecutorCallbackFuzzer OnSetProperty");
        return onSetPropertyResult_;
    }

    int32_t OnGetProperty(std::shared_ptr<AuthAttributes> conditions, std::shared_ptr<AuthAttributes> values) override
    {
        IAM_LOGI("ResIExecutorCallbackFuzzer OnGetProperty");
        return onGetPropertyResult_;
    }

private:
    int32_t onBeginExecuteResult_;
    int32_t onEndExecuteResult_;
    int32_t onSetPropertyResult_;
    int32_t onGetPropertyResult_;
};

class ResIQueryCallbackFuzzer : public IRemoteStub<ResIQueryCallback> {
public:
    virtual ~ResIQueryCallbackFuzzer() = default;
    void OnResult(uint32_t resultCode) override
    {
        IAM_LOGI("ResIQueryCallbackFuzzer OnResult");
        return;
    }
};

void FillFuzzResAuthExecutor(Parcel &parcel, ResAuthExecutor &executorInfo)
{
    executorInfo.SetAuthType(static_cast<AuthType>(parcel.ReadUint32()));
    executorInfo.SetAuthAbility(parcel.ReadUint64());
    executorInfo.SetExecutorSecLevel(static_cast<ExecutorSecureLevel>(parcel.ReadUint32()));
    executorInfo.SetExecutorType(static_cast<ExecutorType>(parcel.ReadUint32()));
    std::vector<uint8_t> publicKey;
    FillFuzzUint8Vector(parcel, publicKey);
    executorInfo.SetPublicKey(publicKey);
    std::vector<uint8_t> deviceId;
    FillFuzzUint8Vector(parcel, deviceId);
    executorInfo.SetDeviceId(deviceId);
    IAM_LOGI("FillFuzzResAuthExecutor success");
}

CoAuthService g_coAuthService(SUBSYS_USERIAM_SYS_ABILITY_AUTHEXECUTORMGR, true);

void FuzzOnStart(Parcel &parcel)
{
    IAM_LOGI("FuzzOnStart begin");
    static_cast<void>(parcel);
    g_coAuthService.OnStart();
    IAM_LOGI("FuzzOnStart end");
}

void FuzzOnStop(Parcel &parcel)
{
    IAM_LOGI("FuzzOnStop begin");
    static_cast<void>(parcel);
    g_coAuthService.OnStop();
    IAM_LOGI("FuzzOnStop end");
}

void FuzzRegister(Parcel &parcel)
{
    IAM_LOGI("FuzzRegister begin");
    auto executorInfo = std::make_shared<ResAuthExecutor>();
    FillFuzzResAuthExecutor(parcel, *executorInfo);
    sptr<ResIExecutorCallback> callback = nullptr;
    if (parcel.ReadBool()) {
        callback = new (std::nothrow)
            ResIExecutorCallbackFuzzer(parcel.ReadInt32(), parcel.ReadInt32(), parcel.ReadInt32(), parcel.ReadInt32());
    }
    g_coAuthService.Register(executorInfo, callback);
    IAM_LOGI("FuzzRegister end");
}

void FuzzQueryStatus(Parcel &parcel)
{
    IAM_LOGI("FuzzQueryStatus begin");
    ResAuthExecutor executorInfo;
    FillFuzzResAuthExecutor(parcel, executorInfo);
    sptr<ResIQueryCallback> callback = nullptr;
    if (parcel.ReadBool()) {
        callback = new (std::nothrow) ResIQueryCallbackFuzzer();
    }
    g_coAuthService.QueryStatus(executorInfo, callback);
    IAM_LOGI("FuzzQueryStatus end");
}

using FuzzFunc = decltype(FuzzOnStart);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzOnStart,
    FuzzOnStop,
    FuzzRegister,
    FuzzQueryStatus,
};

void CoAuthFuzzTest(const uint8_t *data, size_t size)
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
} // namespace CoAuth
} // namespace UserIAM
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::UserIAM::CoAuth::CoAuthFuzzTest(data, size);
    return 0;
}
