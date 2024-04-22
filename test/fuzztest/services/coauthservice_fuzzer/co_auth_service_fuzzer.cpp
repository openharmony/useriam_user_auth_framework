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

#include "co_auth_service_fuzzer.h"

#include "parcel.h"

#include "co_auth_service.h"
#include "executor_messenger_service.h"
#include "executor_callback_interface.h"
#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_TAG "USER_AUTH_SA"

#undef private

using namespace std;
using namespace OHOS::UserIam::Common;
using namespace OHOS::UserIam::UserAuth;
using ExecutorRegisterInfo = CoAuthInterface::ExecutorRegisterInfo;

namespace OHOS {
namespace UserIam {
namespace CoAuth {
namespace {
const int CMD_LEN = 19;
std::u16string cmd[] = {u"-h", u"-lc", u"-ls", u"-c", u"-c [base system]", u"-s", u"-s [SA0 SA1]", u"-s [SA] -a [-h]",
    u"-e", u"--net", u"--storage", u"-p", u"-p [pid]", u"--cpuusage [pid]", u"cified pid", u"--cpufreq", u"--mem [pid]",
    u"--zip", u"--mem-smaps pid [-v]"};

class CoAuthServiceFuzzer : public ExecutorCallbackInterface {
public:
    CoAuthServiceFuzzer(int32_t onBeginExecuteResult, int32_t onEndExecuteResult, int32_t onSetPropertyResult,
        int32_t onGetPropertyResult, int32_t onSendDataResult)
        : onBeginExecuteResult_(onBeginExecuteResult),
          onEndExecuteResult_(onEndExecuteResult),
          onSetPropertyResult_(onSetPropertyResult),
          onGetPropertyResult_(onGetPropertyResult),
          onSendDataResult_(onSendDataResult)
    {
    }

    virtual ~CoAuthServiceFuzzer() = default;

    void OnMessengerReady(uint64_t executorIndex, sptr<ExecutorMessengerInterface> &messenger,
        const std::vector<uint8_t> &publicKey, const std::vector<uint64_t> &templateIdList) override
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

    int32_t OnSendData(uint64_t scheduleId, const Attributes &data) override
    {
        IAM_LOGI("start");
        return onSendDataResult_;
    }

    sptr<IRemoteObject> AsObject() override
    {
        sptr<IRemoteObject> tmp(nullptr);
        return tmp;
    }

private:
    int32_t onBeginExecuteResult_;
    int32_t onEndExecuteResult_;
    int32_t onSetPropertyResult_;
    int32_t onGetPropertyResult_;
    int32_t onSendDataResult_;
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

CoAuthService g_coAuthService;
sptr<ExecutorMessengerService> executorMessengerService = ExecutorMessengerService::GetInstance();

void FuzzRegister(Parcel &parcel)
{
    IAM_LOGI("FuzzRegister begin");
    ExecutorRegisterInfo executorInfo;
    FillFuzzExecutorRegisterInfo(parcel, executorInfo);
    sptr<ExecutorCallbackInterface> callback(nullptr);
    if (parcel.ReadBool()) {
        callback = sptr<ExecutorCallbackInterface>(new (std::nothrow)
            CoAuthServiceFuzzer(parcel.ReadInt32(), parcel.ReadInt32(), parcel.ReadInt32(), parcel.ReadInt32(),
                parcel.ReadInt32()));
    }
    g_coAuthService.ExecutorRegister(executorInfo, callback);
    IAM_LOGI("FuzzRegister end");
}

void FuzzSendData(Parcel &parcel)
{
    IAM_LOGI("FuzzSendData begin");
    uint64_t scheduleId = parcel.ReadUint64();
    ExecutorRole dstRole = static_cast<ExecutorRole>(parcel.ReadInt32());
    std::vector<uint8_t> msg;
    Common::FillFuzzUint8Vector(parcel, msg);

    if (executorMessengerService != nullptr) {
        executorMessengerService->SendData(scheduleId, dstRole, msg);
    }
    IAM_LOGI("FuzzSendData end");
}

void FuzzFinish(Parcel &parcel)
{
    IAM_LOGI("FuzzFinish begin");
    uint64_t scheduleId = parcel.ReadUint64();
    ResultCode resultCode = static_cast<ResultCode>(parcel.ReadInt32());
    auto finalResult = Common::MakeShared<Attributes>();

    if (executorMessengerService != nullptr) {
        executorMessengerService->Finish(scheduleId, resultCode, finalResult);
    }
    IAM_LOGI("FuzzFinish end");
}

void FuzzDump(Parcel &parcel)
{
    IAM_LOGI("FuzzDump begin");
    std::vector<uint8_t> msg;
    Common::FillFuzzUint8Vector(parcel, msg);
    int32_t fd = parcel.ReadInt32();
    std::vector<std::u16string> args;
    for (uint32_t i = 0; i < msg.size(); i++) {
        args.push_back(cmd[msg[i] % CMD_LEN]);
    }
    g_coAuthService.Dump(fd, args);
    IAM_LOGI("FuzzDump end");
}

using FuzzFunc = decltype(FuzzRegister);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzRegister,
    FuzzSendData,
    FuzzFinish,
    FuzzDump,
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
} // namespace UserIam
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::UserIam::CoAuth::CoAuthFuzzTest(data, size);
    return 0;
}
