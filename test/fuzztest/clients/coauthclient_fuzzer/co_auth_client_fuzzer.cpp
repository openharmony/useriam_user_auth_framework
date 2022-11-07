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

#include "co_auth_client_fuzzer.h"

#include "parcel.h"

#include "co_auth_client.h"
#include "executor_callback_service.h"
#include "executor_messenger_client.h"
#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_LABEL OHOS::UserIam::Common::LABEL_USER_AUTH_SDK

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
class DummyExecutorRegisterCallback final : public ExecutorRegisterCallback {
public:
    void OnMessengerReady(const std::shared_ptr<ExecutorMessenger> &messenger,
        const std::vector<uint8_t> &publicKey, const std::vector<uint64_t> &templateIds)
    {
        IAM_LOGI("start");
        static_cast<void>(messenger);
        static_cast<void>(publicKey);
        static_cast<void>(templateIds);
    }

    int32_t OnBeginExecute(uint64_t scheduleId, const std::vector<uint8_t> &publicKey,
        const Attributes &commandAttrs)
    {
        IAM_LOGI("start");
        static_cast<void>(scheduleId);
        static_cast<void>(publicKey);
        static_cast<void>(commandAttrs);
        return SUCCESS;
    }

    int32_t OnEndExecute(uint64_t scheduleId, const Attributes &commandAttrs)
    {
        IAM_LOGI("start");
        static_cast<void>(scheduleId);
        static_cast<void>(commandAttrs);
        return SUCCESS;
    }

    int32_t OnSetProperty(const Attributes &properties)
    {
        IAM_LOGI("start");
        static_cast<void>(properties);
        return SUCCESS;
    }

    int32_t OnGetProperty(const Attributes &conditions, Attributes &results)
    {
        IAM_LOGI("start");
        static_cast<void>(conditions);
        static_cast<void>(results);
        return SUCCESS;
    }
};

class DummyExecutorMessengerInterface final : public ExecutorMessengerInterface {
public:
    int32_t SendData(uint64_t scheduleId, uint64_t transNum, ExecutorRole srcRole, ExecutorRole dstRole,
        const std::vector<uint8_t> &msg) override
    {
        IAM_LOGI("start");
        static_cast<void>(scheduleId);
        static_cast<void>(transNum);
        static_cast<void>(srcRole);
        static_cast<void>(dstRole);
        static_cast<void>(msg);
        return SUCCESS;
    }

    int32_t Finish(uint64_t scheduleId, ExecutorRole srcRole, ResultCode resultCode,
        const std::shared_ptr<Attributes> &finalResult) override
    {
        IAM_LOGI("start");
        static_cast<void>(scheduleId);
        static_cast<void>(srcRole);
        static_cast<void>(resultCode);
        static_cast<void>(finalResult);
        return SUCCESS;
    }

    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }
};

void FillExecutorInfo(Parcel &parcel, ExecutorInfo &info)
{
    info.authType = static_cast<AuthType>(parcel.ReadInt32());
    info.executorRole = static_cast<ExecutorRole>(parcel.ReadInt32());
    info.executorMatcher = parcel.ReadUint32();
    info.executorSensorHint = parcel.ReadUint32();
    info.esl = static_cast<ExecutorSecureLevel>(parcel.ReadInt32());
    Common::FillFuzzUint8Vector(parcel, info.publicKey);
}

void FuzzCoAuthClientRegister(Parcel &parcel)
{
    IAM_LOGI("start");
    ExecutorInfo info = {};
    FillExecutorInfo(parcel, info);
    auto callback = Common::MakeShared<DummyExecutorRegisterCallback>();
    CoAuthClient::GetInstance().Register(info, callback);
    IAM_LOGI("end");
}

void FuzzCoAuthClientUnregister(Parcel &parcel)
{
    IAM_LOGI("start");
    ExecutorInfo info = {};
    FillExecutorInfo(parcel, info);
    CoAuthClient::GetInstance().Unregister(info);
    IAM_LOGI("end");
}

auto g_ExecutorCallbackService =
    Common::MakeShared<ExecutorCallbackService>(Common::MakeShared<DummyExecutorRegisterCallback>());

auto g_ExecutorMessengerClient =
    Common::MakeShared<ExecutorMessengerClient>(new DummyExecutorMessengerInterface());

void FuzzExecutorCallbackServiceOnMessengerReady(Parcel &parcel)
{
    IAM_LOGI("start");
    sptr<ExecutorMessengerInterface> messenger = new DummyExecutorMessengerInterface();
    std::vector<uint8_t> publicKey;
    Common::FillFuzzUint8Vector(parcel, publicKey);
    std::vector<uint64_t> templateIdList;
    Common::FillFuzzUint64Vector(parcel, templateIdList);
    if (g_ExecutorCallbackService != nullptr) {
        g_ExecutorCallbackService->OnMessengerReady(messenger, publicKey, templateIdList);
    }
    IAM_LOGI("end");
}

void FuzzExecutorCallbackServiceOnBeginExecute(Parcel &parcel)
{
    IAM_LOGI("start");
    uint64_t scheduleId = parcel.ReadUint64();
    std::vector<uint8_t> publicKey;
    Common::FillFuzzUint8Vector(parcel, publicKey);
    std::vector<uint8_t> attr;
    Common::FillFuzzUint8Vector(parcel, attr);
    Attributes command(attr);
    if (g_ExecutorCallbackService != nullptr) {
        g_ExecutorCallbackService->OnBeginExecute(scheduleId, publicKey, command);
    }
    IAM_LOGI("end");
}

void FuzzExecutorCallbackServiceOnEndExecute(Parcel &parcel)
{
    IAM_LOGI("start");
    uint64_t scheduleId = parcel.ReadUint64();
    std::vector<uint8_t> attr;
    Common::FillFuzzUint8Vector(parcel, attr);
    Attributes command(attr);
    if (g_ExecutorCallbackService != nullptr) {
        g_ExecutorCallbackService->OnEndExecute(scheduleId, command);
    }
    IAM_LOGI("end");
}

void FuzzExecutorCallbackServiceOnSetProperty(Parcel &parcel)
{
    IAM_LOGI("start");
    std::vector<uint8_t> attr;
    Common::FillFuzzUint8Vector(parcel, attr);
    Attributes properties(attr);
    if (g_ExecutorCallbackService != nullptr) {
        g_ExecutorCallbackService->OnSetProperty(properties);
    }
    IAM_LOGI("end");
}

void FuzzExecutorCallbackServiceOnGetProperty(Parcel &parcel)
{
    IAM_LOGI("start");
    std::vector<uint8_t> attr;
    Common::FillFuzzUint8Vector(parcel, attr);
    Attributes condition(attr);
    Attributes values;
    if (g_ExecutorCallbackService != nullptr) {
        g_ExecutorCallbackService->OnGetProperty(condition, values);
    }
    IAM_LOGI("end");
}

void FuzzExecutorMessengerClientSendData(Parcel &parcel)
{
    IAM_LOGI("start");
    uint64_t scheduleId = parcel.ReadUint64();
    uint64_t transNum = parcel.ReadUint64();
    auto srcRole = static_cast<ExecutorRole>(parcel.ReadInt32());
    auto dstRole = static_cast<ExecutorRole>(parcel.ReadInt32());
    std::vector<uint8_t> testMessage;
    Common::FillFuzzUint8Vector(parcel, testMessage);
    auto msg = AuthMessage::As(testMessage);
    if (g_ExecutorMessengerClient != nullptr) {
        g_ExecutorMessengerClient->SendData(scheduleId, transNum, srcRole, dstRole, msg);
    }
    IAM_LOGI("end");
}

void FuzzExecutorMessengerClientFinish(Parcel &parcel)
{
    IAM_LOGI("start");
    uint64_t scheduleId = parcel.ReadUint64();
    auto srcRole = static_cast<ExecutorRole>(parcel.ReadInt32());
    int32_t resultCode = parcel.ReadInt32();
    std::vector<uint8_t> attr;
    Common::FillFuzzUint8Vector(parcel, attr);
    Attributes finalResult(attr);
    if (g_ExecutorMessengerClient != nullptr) {
        g_ExecutorMessengerClient->Finish(scheduleId, srcRole, resultCode, finalResult);
    }
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzCoAuthClientRegister);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzCoAuthClientRegister,
    FuzzCoAuthClientUnregister,
    FuzzExecutorCallbackServiceOnMessengerReady,
    FuzzExecutorCallbackServiceOnBeginExecute,
    FuzzExecutorCallbackServiceOnEndExecute,
    FuzzExecutorCallbackServiceOnSetProperty,
    FuzzExecutorCallbackServiceOnGetProperty,
    FuzzExecutorMessengerClientSendData,
    FuzzExecutorMessengerClientFinish,
};

void CoAuthClientFuzzTest(const uint8_t *data, size_t size)
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
    OHOS::UserIam::UserAuth::CoAuthClientFuzzTest(data, size);
    return 0;
}
