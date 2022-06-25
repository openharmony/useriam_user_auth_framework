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

#define LOG_LABEL Common::LABEL_USER_AUTH_EXECUTOR

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
namespace {
using namespace std;
using namespace OHOS::UserIAM;
using namespace OHOS::UserIAM::Common;
using namespace OHOS::UserIam::UserAuth;

vector<std::function<void(void)>> g_callbackToReply;
std::mutex g_callbackToReplyMutex;
std::shared_ptr<AuthResPool::ExecutorCallback> g_executorCallback = nullptr;

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
        executorInfo.executorId = fuzzParcel_->ReadInt32();
        executorInfo.authType = static_cast<AuthType>(fuzzParcel_->ReadInt32());
        executorInfo.role = static_cast<ExecutorRole>(fuzzParcel_->ReadInt32());
        executorInfo.executorType = fuzzParcel_->ReadInt32();
        executorInfo.esl = static_cast<ExecutorSecureLevel>(fuzzParcel_->ReadInt32());
        FillFuzzUint8Vector(*fuzzParcel_, executorInfo.publicKey);
        FillFuzzUint8Vector(*fuzzParcel_, executorInfo.deviceId);
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

    ResultCode Enroll(uint64_t scheduleId, uint64_t callerUid, const std::vector<uint8_t> &extraInfo,
        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) override
    {
        FuzzTriggerIExecuteCallback(callbackObj);
        return static_cast<ResultCode>(fuzzParcel_->ReadInt32());
    }

    ResultCode Authenticate(uint64_t scheduleId, uint64_t callerUid, const std::vector<uint64_t> &templateIdList,
        const std::vector<uint8_t> &extraInfo, const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) override
    {
        FuzzTriggerIExecuteCallback(callbackObj);
        return static_cast<ResultCode>(fuzzParcel_->ReadInt32());
    }

    ResultCode Identify(uint64_t scheduleId, uint64_t callerUid, const std::vector<uint8_t> &extraInfo,
        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) override
    {
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

    ResultCode SendCommand(UserAuth::AuthPropertyMode commandId, const std::vector<uint8_t> &extraInfo,
        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) override
    {
        FuzzTriggerIExecuteCallback(callbackObj);
        return static_cast<ResultCode>(fuzzParcel_->ReadInt32());
    }

    void SetParcel(std::shared_ptr<Parcel> &parcel)
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
    void Register(const ExecutorInfo &info, std::shared_ptr<AuthResPool::ExecutorCallback> callback) override
    {
        g_executorCallback = callback;
    }
};

class DummyExecutorMessenger : public IExecutorMessenger {
public:
    int32_t SendData(uint64_t scheduleId, uint64_t transNum, int32_t srcType, int32_t dstType,
        std::shared_ptr<AuthMessage> msg) override
    {
        return fuzzParcel_->ReadInt32();
    }

    int32_t Finish(
        uint64_t scheduleId, int32_t srcType, int32_t resultCode, std::shared_ptr<Attributes> finalResult) override
    {
        return fuzzParcel_->ReadInt32();
    }

    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }

    void SetParcel(std::shared_ptr<Parcel> &parcel)
    {
        fuzzParcel_ = parcel;
    }

private:
    std::shared_ptr<Parcel> fuzzParcel_;
};

auto g_executorHdi = Common::MakeShared<DummyAuthExecutorHdi>();
auto g_executorMgrWrapper = Common::MakeShared<DummyExecutorMgrWrapper>();
auto g_executor = Common::MakeShared<Executor>(g_executorMgrWrapper, g_executorHdi, 1);
sptr<DummyExecutorMessenger> g_executorMessenger = new (std::nothrow) DummyExecutorMessenger();

void FuzzExecutorResetExecutor(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    static uint32_t id = 0;
    id++;
    g_executor = Common::MakeShared<Executor>(g_executorMgrWrapper, g_executorHdi, id);
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

void FillIExecutorMessenger(std::shared_ptr<Parcel> parcel, sptr<IExecutorMessenger> &messenger)
{
    bool fillNull = parcel->ReadBool();
    if (fillNull) {
        messenger = nullptr;
        return;
    }
    messenger = g_executorMessenger;
}

void FillIAttributes(std::shared_ptr<Parcel> parcel, std::shared_ptr<Attributes> &attributes)
{
    bool fillNull = parcel->ReadBool();
    if (fillNull) {
        attributes = nullptr;
        return;
    }
    attributes = MakeShared<Attributes>();
    attributes->SetUint64Value(Attributes::ATTR_TEMPLATE_ID, parcel->ReadUint64());
    attributes->SetUint64Value(Attributes::ATTR_CALLER_UID, parcel->ReadUint64());
    attributes->SetUint32Value(Attributes::ATTR_PROPERTY_MODE, parcel->ReadUint32());
    std::vector<uint64_t> templateIdList;
    FillFuzzUint64Vector(*parcel, templateIdList);
    attributes->GetUint64ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, templateIdList);
    attributes->SetUint64Value(Attributes::ATTR_CALLER_UID, parcel->ReadUint64());
    attributes->SetUint32Value(Attributes::ATTR_SCHEDULE_MODE, parcel->ReadUint32());
}

void FuzzFrameworkOnMessengerReady1(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    // g_executorCallback may be not set
    if (g_executorCallback == nullptr) {
        return;
    }
    sptr<IExecutorMessenger> messenger = nullptr;
    FillIExecutorMessenger(parcel, messenger);
    g_executorCallback->OnMessengerReady(messenger);
    IAM_LOGI("end");
}

void FuzzFrameworkOnMessengerReady2(std::shared_ptr<Parcel> parcel)
{
    IAM_LOGI("begin");
    // g_executorCallback may be not set
    if (g_executorCallback == nullptr) {
        return;
    }
    sptr<IExecutorMessenger> messenger = nullptr;
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
    std::shared_ptr<Attributes> commandAttrs = nullptr;
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
    std::shared_ptr<Attributes> consumerAttr = nullptr;
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
    std::shared_ptr<Attributes> properties = nullptr;
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
    std::shared_ptr<Attributes> conditions = nullptr;
    FillIAttributes(parcel, conditions);
    std::shared_ptr<Attributes> values = nullptr;
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
    FuzzFrameworkOnMessengerReady1,
    FuzzFrameworkOnMessengerReady2,
    FuzzFrameworkOnBeginExecute,
    FuzzFrameworkOnEndExecute,
    FuzzFrameworkOnSetProperty,
    FuzzFrameworkOnGetProperty,
    FuzzTriggerCallback,
};

void UserAuthExecutorFuzzTest(const uint8_t *data, size_t size)
{
    auto parcel = Common::MakeShared<Parcel>();
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
} // namespace UserIAM
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::UserIAM::UserAuth::UserAuthExecutorFuzzTest(data, size);
    return 0;
}
