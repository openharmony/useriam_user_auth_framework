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

#include "schedule_node_fuzzer.h"

#include "common_dummy.h"
#include "schedule_node.h"
#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
std::shared_ptr<ScheduleNode> GetScheduleNode(Parcel &parcel)
{
    IAM_LOGI("start");
    auto authType = static_cast<AuthType>(parcel.ReadInt32());
    auto executorRole = static_cast<ExecutorRole>(parcel.ReadInt32());
    auto esl = static_cast<ExecutorSecureLevel>(parcel.ReadInt32());
    auto builder =
        ScheduleNode::Builder::New(
            Common::MakeShared<DummyResourceNode>(authType, executorRole, esl),
            Common::MakeShared<DummyResourceNode>(authType, executorRole, esl));
    if (builder == nullptr) {
        return nullptr;
    }
    builder->SetScheduleId(parcel.ReadUint64());
    builder->SetAccessTokenId(parcel.ReadUint32());
    builder->SetPinSubType(static_cast<PinSubType>(parcel.ReadInt32()));
    builder->SetAuthType(static_cast<AuthType>(parcel.ReadInt32()));
    builder->SetExecutorMatcher(parcel.ReadUint32());
    std::vector<uint64_t> templateIdList;
    Common::FillFuzzUint64Vector(parcel, templateIdList);
    builder->SetTemplateIdList(templateIdList);
    std::string additionalInfo = parcel.ReadString();
    builder->SetAdditionalInfo(additionalInfo);

    return builder->Build();
}

void FuzzScheduleNodeGetScheduleId(Parcel &parcel)
{
    IAM_LOGI("start");
    auto node = GetScheduleNode(parcel);
    if (node != nullptr) {
        node->GetScheduleId();
    }
    IAM_LOGI("end");
}

void FuzzScheduleNodeGetContextId(Parcel &parcel)
{
    IAM_LOGI("start");
    auto node = GetScheduleNode(parcel);
    if (node != nullptr) {
        node->GetContextId();
    }
    IAM_LOGI("end");
}

void FuzzScheduleNodeGetAuthType(Parcel &parcel)
{
    IAM_LOGI("start");
    auto node = GetScheduleNode(parcel);
    if (node != nullptr) {
        node->GetAuthType();
    }
    IAM_LOGI("end");
}

void FuzzScheduleNodeGetExecutorMatcher(Parcel &parcel)
{
    IAM_LOGI("start");
    auto node = GetScheduleNode(parcel);
    if (node != nullptr) {
        node->GetExecutorMatcher();
    }
    IAM_LOGI("end");
}

void FuzzScheduleNodeGetScheduleMode(Parcel &parcel)
{
    IAM_LOGI("start");
    auto node = GetScheduleNode(parcel);
    if (node != nullptr) {
        node->GetScheduleMode();
    }
    IAM_LOGI("end");
}

void FuzzScheduleNodeGetCollectorExecutor(Parcel &parcel)
{
    IAM_LOGI("start");
    auto node = GetScheduleNode(parcel);
    if (node != nullptr) {
        node->GetCollectorExecutor();
    }
    IAM_LOGI("end");
}

void FuzzScheduleNodeGetVerifyExecutor(Parcel &parcel)
{
    IAM_LOGI("start");
    auto node = GetScheduleNode(parcel);
    if (node != nullptr) {
        node->GetVerifyExecutor();
    }
    IAM_LOGI("end");
}

void FuzzScheduleNodeGetTemplateIdList(Parcel &parcel)
{
    IAM_LOGI("start");
    auto node = GetScheduleNode(parcel);
    if (node != nullptr) {
        node->GetTemplateIdList();
    }
    IAM_LOGI("end");
}

void FuzzScheduleNodeGetCurrentScheduleState(Parcel &parcel)
{
    IAM_LOGI("start");
    auto node = GetScheduleNode(parcel);
    if (node != nullptr) {
        node->GetCurrentScheduleState();
    }
    IAM_LOGI("end");
}

void FuzzScheduleNodeStartSchedule(Parcel &parcel)
{
    IAM_LOGI("start");
    auto node = GetScheduleNode(parcel);
    if (node != nullptr) {
        node->StartSchedule();
    }
    IAM_LOGI("end");
}

void FuzzScheduleNodeStopSchedule(Parcel &parcel)
{
    IAM_LOGI("start");
    auto node = GetScheduleNode(parcel);
    if (node != nullptr) {
        node->StopSchedule();
    }
    IAM_LOGI("end");
}

void FuzzScheduleNodeSendMessage(Parcel &parcel)
{
    IAM_LOGI("start");
    auto dstRole = static_cast<ExecutorRole>(parcel.ReadInt32());
    std::vector<uint8_t> msg;
    Common::FillFuzzUint8Vector(parcel, msg);
    auto node = GetScheduleNode(parcel);
    if (node != nullptr) {
        node->SendMessage(dstRole, msg);
    }
    IAM_LOGI("end");
}

void FuzzScheduleNodeContinueSchedule(Parcel &parcel)
{
    IAM_LOGI("start");
    auto resultCode = static_cast<ResultCode>(parcel.ReadInt32());
    std::vector<uint8_t> attr;
    Common::FillFuzzUint8Vector(parcel, attr);
    auto finalResult = Common::MakeShared<Attributes>(attr);
    auto node = GetScheduleNode(parcel);
    if (node != nullptr) {
        node->ContinueSchedule(resultCode, finalResult);
    }
    IAM_LOGI("end");
}

using ScheduleNodeFuzzFunc = decltype(FuzzScheduleNodeGetScheduleId);
ScheduleNodeFuzzFunc *g_ScheduleNodeFuzzFuncs[] = {
    FuzzScheduleNodeGetScheduleId,
    FuzzScheduleNodeGetContextId,
    FuzzScheduleNodeGetAuthType,
    FuzzScheduleNodeGetExecutorMatcher,
    FuzzScheduleNodeGetScheduleMode,
    FuzzScheduleNodeGetCollectorExecutor,
    FuzzScheduleNodeGetVerifyExecutor,
    FuzzScheduleNodeGetTemplateIdList,
    FuzzScheduleNodeGetCurrentScheduleState,
    FuzzScheduleNodeStartSchedule,
    FuzzScheduleNodeStopSchedule,
    FuzzScheduleNodeSendMessage,
    FuzzScheduleNodeContinueSchedule,
};
} // namespace

void ScheduleNodeFuzzTest(Parcel &parcel)
{
    uint32_t index = parcel.ReadUint32() % (sizeof(g_ScheduleNodeFuzzFuncs) / sizeof(ScheduleNodeFuzzFunc *));
    auto fuzzFunc = g_ScheduleNodeFuzzFuncs[index];
    fuzzFunc(parcel);
    return;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
