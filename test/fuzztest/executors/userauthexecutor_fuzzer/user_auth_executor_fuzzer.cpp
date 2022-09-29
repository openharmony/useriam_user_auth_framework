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

#include "user_auth_executor_fuzzer.h"

#include <cstdint>
#include <functional>

#include "executor.h"
#include "executor_mgr_wrapper.h"
#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "iauth_executor_hdi.h"

#undef private

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_EXECUTOR

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
using namespace std;
using namespace OHOS::UserIam::Common;
using namespace OHOS::UserIam::UserAuth;

vector<std::function<void(void)>> g_callbackToReply;
std::mutex g_callbackToReplyMutex;
std::shared_ptr<ExecutorRegisterCallback> g_executorCallback = nullptr;

class DummyAuthExecutorHdi : public IAuthExecutorHdi {
public:
    DummyAuthExecutorHdi() = default;
    ~DummyAuthExecutorHdi() override = default;

    ResultCode GetExecutorInfo(ExecutorInfo &executorInfo) override
    {
        // GetExecutorInfo is called in Executor constructor, when fuzzParcel_ is null
        // or g_executorCallback is not registered, SUCCESS is returned to prompt other test
        if (fuzzParcel_ == nullptr || g_executorCallback == nullptr) {
            return ResultCode::SUCCESS;
        }
        executorInfo.executorSensorHint = fuzzParcel_->ReadInt32();
        executorInfo.authType = static_cast<AuthType>(fuzzParcel_->ReadInt32());
        executorInfo.executorRole = static_cast<ExecutorRole>(fuzzParcel_->ReadInt32());
        executorInfo.executorMatcher = fuzzParcel_->ReadInt32();
        executorInfo.esl = static_cast<ExecutorSecureLevel>(fuzzParcel_->ReadInt32());
        FillFuzzUint8Vector(*fuzzParcel_, executorInfo.publicKey);
        return static_cast<ResultCode>(fuzzParcel_->ReadInt32());
    }

    ResultCode GetTemplateInfo(uint64_t templateId, UserAuth::TemplateInfo &templateInfo) override
    {
        templateInfo.executorType = fuzzParcel_->ReadUint32();
        templateInfo.freezingTime = fuzzParcel_->ReadInt32();
        templateInfo.remainTimes = fuzzParcel_->ReadInt32();
        FillFuzzUint8Vector(*fuzzParcel_, templateInfo.extraInfo);
        return static_cast<ResultCode>(fuzzParcel_->ReadInt32());
    }

    ResultCode OnRegisterFinish(const std::vector<uint64_t> &templateIdList,
        const std::vector<uint8_t> &frameworkPublicKey, const std::vector<uint8_t> &extraInfo) override
    {
        return static_cast<ResultCode>(fuzzParcel_->ReadInt32());
    }

    ResultCode Enroll(uint64_t scheduleId, uint32_t tokenId, const std::vector<uint8_t> &extraInfo,
        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) override
    {
        static_cast<void>(scheduleId);
        static_cast<void>(tokenId);
        static_cast<void>(extraInfo);
        FuzzTriggerIExecuteCallback(callbackObj);
        return static_cast<ResultCode>(fuzzParcel_->ReadInt32());
    }

    ResultCode Authenticate(uint64_t scheduleId, uint32_t tokenId, const std::vector<uint64_t> &templateIdList,
        const std::vector<uint8_t> &extraInfo, const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) override
    {
        static_cast<void>(scheduleId);
        static_cast<void>(tokenId);
        static_cast<void>(templateIdList);
        static_cast<void>(extraInfo);
        FuzzTriggerIExecuteCallback(callbackObj);
        return static_cast<ResultCode>(fuzzParcel_->ReadInt32());
    }

    ResultCode Identify(uint64_t scheduleId, uint32_t tokenId, const std::vector<uint8_t> &extraInfo,
        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) override
    {
        static_cast<void>(scheduleId);
        static_cast<void>(tokenId);
        static_cast<void>(extraInfo);
        FuzzTriggerIExecuteCallback(callbackObj);
        return static_cast<ResultCode>(fuzzParcel_->ReadInt32());
    }

    ResultCode Delete(const std::vector<uint64_t> &templateIdList) override
    {
        return static_cast<ResultCode>(fuzzParcel_->ReadInt32());
    }

    ResultCode Cancel(uint64_t scheduleId) override
    {
        return static_cast<ResultCode>(fuzzParcel_->ReadInt32());
    }

    ResultCode SendCommand(PropertyMode commandId, const std::vector<uint8_t> &extraInfo,
        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) override
    {
        FuzzTriggerIExecuteCallback(callbackObj);
        return static_cast<ResultCode>(fuzzParcel_->ReadInt32());
    }

    void SetParcel(const std::shared_ptr<Parcel> &parcel)
    {
        fuzzParcel_ = parcel;
    }

private:
    void FuzzTriggerIExecuteCallback(const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj)
    {
        auto reply = [fuzzParcel(this->fuzzParcel_), callbackObj]() {
            const uint32_t max_trigger_count = 5;
            uint32_t trigger_count = fuzzParcel->ReadUint32() % max_trigger_count;
            vector<uint8_t> extraInfo;
            for (uint32_t i = 0; i < trigger_count; i++) {
                FillFuzzUint8Vector(*fuzzParcel, extraInfo);
                bool triggerOnResult = fuzzParcel->ReadBool();
                if (triggerOnResult) {
                    callbackObj->OnAcquireInfo(fuzzParcel->ReadInt32(), extraInfo);
                } else {
                    callbackObj->OnResult(static_cast<ResultCode>(fuzzParcel->ReadInt32()), extraInfo);
                }
            }
        };

        bool instantReply = fuzzParcel_->ReadBool();
        if (instantReply) {
            reply();
        }
        bool delayedReply = fuzzParcel_->ReadBool();
        if (delayedReply) {
            std::lock_guard<std::mutex> guard(g_callbackToReplyMutex);
            g_callbackToReply.push_back(reply);
        }
    }
    std::shared_ptr<Parcel> fuzzParcel_ = nullptr;
};

class DummyExecutorMgrWrapper : public ExecutorMgrWrapper {
public:
    virtual ~DummyExecutorMgrWrapper() = default;
    void Register(const ExecutorInfo &info, std::shared_ptr<ExecutorRegisterCallback> callback) override
    {
        g_executorCallback = callback;
    }
};

class DummyExecutorMessenger : public ExecutorMessenger {
public:
    virtual ~DummyExecutorMessenger() = default;
    int32_t SendData(uint64_t scheduleId, uint64_t transNum, ExecutorRole srcRole, ExecutorRole dstRole,
        const std::shared_ptr<AuthMessage> &msg) override
    {
        static_cast<void>(scheduleId);
        static_cast<void>(transNum);
        static_cast<void>(srcRole);
        static_cast<void>(dstRole);
        static_cast<void>(msg);
        return fuzzParcel_->ReadInt32();
    }

    int32_t Finish(uint64_t scheduleId, ExecutorRole srcRole, int32_t resultCode,
        const Attributes &finalResult) override
    {
        static_cast<void>(scheduleId);
        static_cast<void>(srcRole);
        static_cast<void>(resultCode);
        static_cast<void>(finalResult);
        return fuzzParcel_->ReadInt32();
    }

    void SetParcel(const std::shared_ptr<Parcel> &parcel)
    {
        fuzzParcel_ = parcel;
    }

private:
    std::shared_ptr<Parcel> fuzzParcel_;
};

auto g_executorHdi = UserIam::Common::MakeShared<DummyAuthExecutorHdi>();
auto g_executorMgrWrapper = UserIam::Common::MakeShared<DummyExecutorMgrWrapper>();
auto g_executor = UserIam::Common::MakeShared<Executor>(g_executorMgrWrapper, g_executorHdi, 1);
auto g_executorMessenger = UserIam::Common::MakeShared<DummyExecutorMessenger>();

void FuzzExecutorResetExecutor(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    static uint32_t id = 0;
    id++;
    g_executor = UserIam::Common::MakeShared<Executor>(g_executorMgrWrapper, g_executorHdi, id);
    IAM_LOGI("end");
}

void FuzzExecutorOnHdiConnect(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    g_executor->OnHdiConnect();
    IAM_LOGI("end");
}

void FuzzExecutorOnHdiDisconnect(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    static int32_t skip_count = 1000;
    // OnHdiDisconnect affects test of other function, skip it in the first phase
    if (skip_count > 0) {
        skip_count--;
        return;
    }
    g_executor->OnHdiDisconnect();
    g_executorCallback = nullptr;
    IAM_LOGI("end");
}

void FuzzExecutorOnFrameworkReady(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    g_executor->OnFrameworkReady();
    IAM_LOGI("end");
}

void FuzzExecutorGetExecutorHdi(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    g_executor->GetExecutorHdi();
    IAM_LOGI("end");
}

void FuzzExecutorGetDescription(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    g_executor->GetDescription();
    IAM_LOGI("end");
}

void FillIExecutorMessenger(std::shared_ptr<Parcel> parcel, shared_ptr<ExecutorMessenger> &messenger)
{
    bool fillNull = parcel->ReadBool();
    if (fillNull) {
        messenger = nullptr;
        return;
    }
    messenger = g_executorMessenger;
}

void FillIAttributes(std::shared_ptr<Parcel> parcel, Attributes &attributes)
{
    bool fillNull = parcel->ReadBool();
    if (fillNull) {
        return;
    }

    attributes.SetUint64Value(Attributes::ATTR_TEMPLATE_ID, parcel->ReadUint64());
    attributes.SetUint64Value(Attributes::ATTR_CALLER_UID, parcel->ReadUint64());
    attributes.SetUint32Value(Attributes::ATTR_PROPERTY_MODE, parcel->ReadUint32());
    std::vector<uint64_t> templateIdList;
    FillFuzzUint64Vector(*parcel, templateIdList);
    attributes.GetUint64ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, templateIdList);
    std::vector<uint8_t> extraInfo;
    FillFuzzUint8Vector(*parcel, extraInfo);
    attributes.GetUint64ArrayValue(Attributes::ATTR_EXTRA_INFO, templateIdList);
    attributes.SetUint64Value(Attributes::ATTR_CALLER_UID, parcel->ReadUint64());
    attributes.SetUint32Value(Attributes::ATTR_SCHEDULE_MODE, parcel->ReadUint32());
}

void FuzzFrameworkOnMessengerReady(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    // g_executorCallback may be not set
    if (g_executorCallback == nullptr) {
        return;
    }
    shared_ptr<ExecutorMessenger> messenger = nullptr;
    FillIExecutorMessenger(parcel, messenger);
    std::vector<uint8_t> publicKey;
    FillFuzzUint8Vector(*parcel, publicKey);
    std::vector<uint64_t> templateIds;
    FillFuzzUint64Vector(*parcel, templateIds);
    g_executorCallback->OnMessengerReady(messenger, publicKey, templateIds);
    IAM_LOGI("end");
}

void FuzzFrameworkOnBeginExecute(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    // g_executorCallback may be not set
    if (g_executorCallback == nullptr) {
        return;
    }
    uint64_t scheduleId = parcel->ReadUint64();
    std::vector<uint8_t> publicKey;
    FillFuzzUint8Vector(*parcel, publicKey);
    Attributes commandAttrs;
    FillIAttributes(parcel, commandAttrs);
    g_executorCallback->OnBeginExecute(scheduleId, publicKey, commandAttrs);
    IAM_LOGI("end");
}

void FuzzFrameworkOnEndExecute(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    // g_executorCallback may be not set
    if (g_executorCallback == nullptr) {
        return;
    }
    uint64_t scheduleId = parcel->ReadUint64();
    Attributes consumerAttr;
    FillIAttributes(parcel, consumerAttr);
    g_executorCallback->OnEndExecute(scheduleId, consumerAttr);
    IAM_LOGI("end");
}

void FuzzFrameworkOnSetProperty(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    // g_executorCallback may be not set
    if (g_executorCallback == nullptr) {
        return;
    }
    Attributes properties;
    FillIAttributes(parcel, properties);
    g_executorCallback->OnSetProperty(properties);
    IAM_LOGI("end");
}

void FuzzFrameworkOnGetProperty(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    // g_executorCallback may be not set
    if (g_executorCallback == nullptr) {
        return;
    }
    Attributes conditions;
    FillIAttributes(parcel, conditions);
    Attributes values;
    FillIAttributes(parcel, values);
    g_executorCallback->OnGetProperty(conditions, values);
    IAM_LOGI("end");
}

void FuzzTriggerCallback(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    std::lock_guard<std::mutex> guard(g_callbackToReplyMutex);
    IAM_LOGI("trigger callback num %{public}zu", g_callbackToReply.size());
    for (const auto &reply : g_callbackToReply) {
        reply();
    }
    g_callbackToReply.clear();
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzFrameworkOnGetProperty);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzExecutorResetExecutor,
    FuzzExecutorOnHdiConnect,
    FuzzExecutorOnHdiDisconnect,
    FuzzExecutorOnFrameworkReady,
    FuzzExecutorGetExecutorHdi,
    FuzzExecutorGetDescription,
    FuzzFrameworkOnMessengerReady,
    FuzzFrameworkOnBeginExecute,
    FuzzFrameworkOnEndExecute,
    FuzzFrameworkOnSetProperty,
    FuzzFrameworkOnGetProperty,
    FuzzTriggerCallback,
};

void UserAuthExecutorFuzzTest(const uint8_t *data, size_t size)
{
    auto parcel = UserIam::Common::MakeShared<Parcel>();
    if (parcel == nullptr) {
        IAM_LOGI("parcel is null");
        return;
    }
    parcel->WriteBuffer(data, size);
    parcel->RewindRead(0);
    uint32_t index = parcel->ReadUint32() % (sizeof(g_fuzzFuncs)) / sizeof(FuzzFunc *);
    g_executorHdi->SetParcel(parcel);
    g_executorMessenger->SetParcel(parcel);
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
    OHOS::UserIam::UserAuth::UserAuthExecutorFuzzTest(data, size);
    return 0;
}
