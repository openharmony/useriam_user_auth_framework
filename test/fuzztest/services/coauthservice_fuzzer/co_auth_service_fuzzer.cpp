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

#include "co_auth_service_fuzzer.h"

#include "parcel.h"

#include "co_auth_service.h"
#include "executor_callback_interface.h"
#include "iam_fuzz_test.h"
#include "iam_logger.h"

#define LOG_LABEL OHOS::UserIAM::Common::LABEL_USER_AUTH_SA

#undef private

using namespace std;
using namespace OHOS::UserIAM::Common;
using namespace OHOS::UserIam::UserAuth;
using ExecutorRegisterInfo = CoAuthInterface::ExecutorRegisterInfo;

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
namespace {
class CoAuthServiceFuzzer : public ExecutorCallbackInterface {
public:
    CoAuthServiceFuzzer(int32_t onBeginExecuteResult, int32_t onEndExecuteResult, int32_t onSetPropertyResult,
        int32_t onGetPropertyResult)
        : onBeginExecuteResult_(onBeginExecuteResult),
          onEndExecuteResult_(onEndExecuteResult),
          onSetPropertyResult_(onSetPropertyResult),
          onGetPropertyResult_(onGetPropertyResult)
    {
    }

    virtual ~CoAuthServiceFuzzer() = default;

    void OnMessengerReady(sptr<ExecutorMessengerInterface> &messenger, const std::vector<uint8_t> &publicKey,
        const std::vector<uint64_t> &templateIdList) override
    {
        IAM_LOGI("start");
        return;
    }

    int32_t OnBeginExecute(uint64_t scheduleId, const std::vector<uint8_t> &publicKey,
        const Attributes &command) override
    {
        IAM_LOGI("start");
        return onBeginExecuteResult_;
    }

    int32_t OnEndExecute(uint64_t scheduleId, const Attributes &command) override
    {
        IAM_LOGI("start");
        return onEndExecuteResult_;
    }

    int32_t OnSetProperty(const Attributes &properties) override
    {
        IAM_LOGI("start");
        return onSetPropertyResult_;
    }

    int32_t OnGetProperty(const Attributes &condition, Attributes &values) override
    {
        IAM_LOGI("start");
        return onGetPropertyResult_;
    }

    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }

private:
    int32_t onBeginExecuteResult_;
    int32_t onEndExecuteResult_;
    int32_t onSetPropertyResult_;
    int32_t onGetPropertyResult_;
};

void FillFuzzExecutorRegisterInfo(Parcel &parcel, ExecutorRegisterInfo &executorInfo)
{
    executorInfo.authType = static_cast<UserIam::UserAuth::AuthType>(parcel.ReadInt32());
    executorInfo.executorRole = static_cast<UserIam::UserAuth::ExecutorRole>(parcel.ReadInt32());
    executorInfo.executorSensorHint = parcel.ReadUint32();
    executorInfo.executorMatcher = parcel.ReadUint32();
    executorInfo.esl = static_cast<UserIam::UserAuth::ExecutorSecureLevel>(parcel.ReadInt32());
    FillFuzzUint8Vector(parcel, executorInfo.publicKey);
    IAM_LOGI("FillFuzzExecutorRegisterInfo success");
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
    ExecutorRegisterInfo executorInfo;
    FillFuzzExecutorRegisterInfo(parcel, executorInfo);
    sptr<ExecutorCallbackInterface> callback = nullptr;
    if (parcel.ReadBool()) {
        callback = new (std::nothrow)
            CoAuthServiceFuzzer(parcel.ReadInt32(), parcel.ReadInt32(), parcel.ReadInt32(), parcel.ReadInt32());
    }
    g_coAuthService.ExecutorRegister(executorInfo, callback);
    IAM_LOGI("FuzzRegister end");
}

using FuzzFunc = decltype(FuzzOnStart);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzOnStart,
    FuzzOnStop,
    FuzzRegister,
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
