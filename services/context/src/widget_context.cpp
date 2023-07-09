/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "widget_context.h"

#include <algorithm>

#include "context_helper.h"
#include "context_pool.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "schedule_node.h"
#include "schedule_node_callback.h"
#include "widget_schedule_node_impl.h"
#include "widget_context_callback_impl.h"
#include "widget_client.h"
#include "widget_json.h"
#include "bool_wrapper.h"
#include "double_wrapper.h"
#include "int_wrapper.h"
#include "string_wrapper.h"
#include "want_params_wrapper.h"
#include "ability_connection.h"
#include "ability_connect_callback.h"
#include "refbase.h"
#include "widget_json.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SA
constexpr int32_t DEFAULT_VALUE = -1;
constexpr int32_t USERIAM_IPC_THREAD_NUM = 4;

namespace OHOS {
namespace UserIam {
namespace UserAuth {

#define IN_PROCESS_CALL(theCall)                                     \
    ([&]() {                                                         \
        std::string identity = IPCSkeleton::ResetCallingIdentity();  \
        auto retVal = theCall;                                       \
        IPCSkeleton::SetCallingIdentity(identity);                   \
        return retVal;                                               \
    }())

WidgetContext::WidgetContext(uint64_t contextId, const ContextFactory::AuthWidgetContextPara &para,
    std::shared_ptr<ContextCallback> callback, int32_t userId, uint32_t tokenId)
    : BaseContext("UserAuthWidget", contextId, callback), para_(para), userId_(userId),
    tokenId_(tokenId), connection_(nullptr)
{
}

WidgetContext::~WidgetContext()
{
    IAM_LOGI("release WidgetContext");
}

ContextType WidgetContext::GetContextType() const
{
    return WIDGET_AUTH_CONTEXT;
}

uint32_t WidgetContext::GetTokenId() const
{
    return para_.tokenId;
}

bool WidgetContext::BuildSchedule()
{
    schedule_ = std::make_shared<WidgetScheduleNodeImpl>();
    schedule_->SetCallback(this);
    IF_FALSE_LOGE_AND_RETURN_VAL(schedule_ != nullptr, false);
    return true;
}

std::shared_ptr<ContextCallback> WidgetContext::GetAuthContextCallback(AuthType authType,
    AuthTrustLevel authTrustLevel, std::shared_ptr<IamCallbackInterface> &callback)
{
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return nullptr;
    }
    auto contextCallback = ContextCallback::NewInstance(callback.get(), TRACE_AUTH_USER);
    if (contextCallback == nullptr) {
        IAM_LOGE("failed to construct context callback");
        Attributes extraInfo;
        callback->OnResult(ResultCode::GENERAL_ERROR, extraInfo);
        return nullptr;
    }
    auto callingUid = static_cast<uint64_t>(para_.callingUid);
    contextCallback->SetTraceCallingUid(callingUid);
    contextCallback->SetTraceAuthType(authType);
    contextCallback->SetTraceAuthTrustLevel(authTrustLevel);
    return contextCallback;
}

std::shared_ptr<Context> WidgetContext::BuildTask(const std::vector<uint8_t> &challenge,
    AuthType authType, AuthTrustLevel authTrustLevel)
{
    userId_ = WidgetClient::Instance().GetUserId();
    tokenId_ = WidgetClient::Instance().GetTokenId();
    IAM_LOGI("Real userId: %{public}d, Real tokenId: %{public}d", userId_, tokenId_);
    std::shared_ptr<IamCallbackInterface> iamCallback =
        std::make_shared<WidgetContextCallbackImpl>(this, static_cast<int32_t>(authType));
    auto contextCallback = GetAuthContextCallback(authType, authTrustLevel, iamCallback);
    callback_->SetTraceUserId(userId_);
    ContextFactory::AuthContextPara para = {};
    para.tokenId = tokenId_;
    para.userId = userId_;
    para.authType = authType;
    para.atl = authTrustLevel;
    para.challenge = challenge;
    para.endAfterFirstFail = true;
    auto context = ContextFactory::CreateSimpleAuthContext(para, contextCallback);
    if (!ContextPool::Instance().Insert(context)) {
        IAM_LOGE("failed to insert context");
        Attributes extraInfo;
        callback_->OnResult(ResultCode::GENERAL_ERROR, extraInfo);
        return nullptr;
    }
    contextCallback->SetCleaner(ContextHelper::Cleaner(context));
    std::lock_guard<std::recursive_mutex> lck(mutex_);
    iam2TaskMap_[iamCallback] = context;
    return context;
}

std::shared_ptr<Context> WidgetContext::GetTaskFromIamcallback(
    const std::shared_ptr<IamCallbackInterface> &iamCallback)
{
    std::lock_guard<std::recursive_mutex> lck(mutex_);
    auto it = iam2TaskMap_.find(iamCallback);
    if (it != iam2TaskMap_.end()) {
        return it->second;
    }
    return nullptr;
}

bool WidgetContext::OnStart()
{
    IAM_LOGI("%{public}s start", GetDescription());
    if (!BuildSchedule()) {
        IAM_LOGE("failed to create widget schedule");
        return false;
    }
    WidgetClient::Instance().SetWidgetContextId(GetContextId());
    WidgetClient::Instance().SetWidgetParam(para_.widgetParam);
    WidgetClient::Instance().SetWidgetSchedule(schedule_);
    schedule_->StartSchedule();

    IPCSkeleton::SetMaxWorkThreadNum(USERIAM_IPC_THREAD_NUM);
    IAM_LOGI("WidgetContext start success.");

    return true;
}

void WidgetContext::OnResult(int32_t resultCode, const std::shared_ptr<Attributes> &scheduleResultAttr)
{
    IAM_LOGI("%{public}s receive result code %{public}d", GetDescription(), resultCode);
}

bool WidgetContext::OnStop()
{
    // response app.cancel()
    IAM_LOGI("%{public}s start", GetDescription());
    End(ResultCode::CANCELED);
    return true;
}

void WidgetContext::AuthResult(int32_t resultCode, int32_t at, const Attributes &finalResult,
    const std::shared_ptr<Context> &task)
{
    IAM_LOGI("recv task result: %{public}d, authType: %{public}d", resultCode, at);
    if (!TaskRun2Done(task)) {
        IAM_LOGE("ignore this task result");
        return;
    }
    int32_t remainTimes = -1;
    int32_t freezingTime = -1;
    finalResult.GetInt32Value(Attributes::ATTR_REMAIN_TIMES, remainTimes);
    finalResult.GetInt32Value(Attributes::ATTR_FREEZING_TIME, freezingTime);
    AuthType authType = static_cast<AuthType>(at);
    WidgetClient::Instance().ReportWidgetResult(resultCode, authType, freezingTime, remainTimes);

    IAM_LOGI("call schedule:");
    if (resultCode == 0) {
        schedule_->SuccessAuth(authType);
    } else {
        // failed
        schedule_->StopAuthList({authType});
    }
}

bool WidgetContext::TaskRun2Done(const std::shared_ptr<Context> &task)
{
    std::lock_guard<std::recursive_mutex> lck(mutex_);
    auto it = std::find_if(runTaskInfoList_.begin(),
        runTaskInfoList_.end(), [&task](const TaskInfo &taskInfo) {
        return (taskInfo.task == task);
    });
    if (it != runTaskInfoList_.end()) {
        doneTaskInfoList_.push_back(*it);
        runTaskInfoList_.erase(it);
        return true;
    }
    return false;
}

// WidgetScheduleNodeCallback
void WidgetContext::LaunchWidget()
{
    IAM_LOGI("launch widget");
    if (!ConnectExtension()) {
        IAM_LOGE("failed to launch widget.");
    }
}

void WidgetContext::ExecuteAuthList(const std::set<AuthType> &authTypeList)
{
    IAM_LOGI("execute auth list");
    // create task, and start it
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    for (auto &authType : authTypeList) {
        auto task = BuildTask(para_.challenge, authType, para_.atl);
        if (task == nullptr) {
            IAM_LOGE("failed to create task, authType: %{public}s", AuthType2Str(authType).c_str());
            continue;
        }
        task->Start();
        TaskInfo taskInfo {
            .authType = authType,
            .task = task
        };
        runTaskInfoList_.push_back(taskInfo);
    }
}

void WidgetContext::EndAuthAsCancel()
{
    IAM_LOGI("end auth as cancel");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    // report CANCELED to App
    End(ResultCode::CANCELED);
}

void WidgetContext::EndAuthAsNaviPin()
{
    IAM_LOGI("end auth as navi pin");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    // report CANCELED_FROM_WIDGET to App
    End(ResultCode::CANCELED_FROM_WIDGET);
}

void WidgetContext::StopAuthList(const std::vector<AuthType> &authTypeList)
{
    IAM_LOGI("stop auth list");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    for (auto &authType : authTypeList) {
        auto it = std::find_if(runTaskInfoList_.begin(),
            runTaskInfoList_.end(), [authType] (const TaskInfo &taskInfo) {
            return (taskInfo.authType == authType);
        });
        if (it != runTaskInfoList_.end()) {
            it->task->Stop();
            doneTaskInfoList_.push_back(*it);
            runTaskInfoList_.erase(it);
        }
    }
}

void WidgetContext::SuccessAuth(AuthType authType)
{
    IAM_LOGI("success auth. authType:%{public}d", static_cast<int32_t>(authType));
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    // report success to App
    End(ResultCode::SUCCESS);
}

void WidgetContext::SetTokenIdByWidget(uint32_t tokenId)
{
    IAM_LOGI("update tokenId from widget from [%{public}d] to [%{public}d]", tokenId_, tokenId);
    tokenId_ = tokenId;
}

int32_t WidgetContext::ConnectExtensionAbility(const AAFwk::Want &want, const std::string commandStr)
{
    IAM_LOGI("ConnectExtensionAbility start");
    ErrCode errCode = AAFwk::AbilityManagerClient::GetInstance()->Connect();
    if (errCode != ERR_OK) {
        IAM_LOGE("connect ability server failed errCode=%{public}d", errCode);
        return errCode;
    }
    if (connection_ == nullptr) {
        IAM_LOGE("connection is nullptr");
        connection_ = new UIExtensionAbilityConnection(commandStr);
    }
    auto ret = IN_PROCESS_CALL(AAFwk::AbilityManagerClient::GetInstance()->ConnectAbility(want,
        connection_, DEFAULT_VALUE));
    IAM_LOGI("ConnectExtensionAbility errCode=%{public}d", ret);
    return ret;
}

// Impl
bool WidgetContext::ConnectExtension()
{
    std::string tmp = BuildStartCommand();
    IAM_LOGI("start command: %{public}s", tmp.c_str());

    auto amsClient = AAFwk::AbilityManagerClient::GetInstance();
    if (amsClient == nullptr) {
        IAM_LOGE("get abiliby manaber client failed.");
        return false;
    }
    AAFwk::Want want;
    std::string bundleName = "com.ohos.systemui";
    std::string abilityName = "com.ohos.systemui.dialog";
    want.SetElementName(bundleName, abilityName);
    auto ret = ConnectExtensionAbility(want, tmp);
    if (ret != ERR_OK) {
        IAM_LOGE("ConnectExtensionAbility failed.");
        return false;
    }
    return true;
}

bool WidgetContext::DisconnectExtension()
{
    if (abilityConnection_ == nullptr) {
        return true;
    }
    auto amsClient = AAFwk::AbilityManagerClient::GetInstance();
    if (amsClient == nullptr) {
        IAM_LOGE("get abiliby manaber client failed.");
        return false;
    }
    ErrCode ret = amsClient->DisconnectAbility(abilityConnection_);
    if (ret != ERR_OK) {
        IAM_LOGE("disconnect extension ability failed ret: %{public}d.", ret);
        return false;
    }
    return true;
}

void WidgetContext::End(const ResultCode &resultCode)
{
    IAM_LOGI("in End, resultCode: %{public}d", static_cast<int32_t>(resultCode));
    WidgetClient::Instance().Reset();
    StopAllRunTask();
    if (!DisconnectExtension()) {
        IAM_LOGE("failed to release launch widget.");
    }
    Attributes attr;
    callback_->OnResult(resultCode, attr); // auto remove this context
}

void WidgetContext::StopAllRunTask()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    for (auto &taskInfo : runTaskInfoList_) {
        IAM_LOGI("stop task");
        taskInfo.task->Stop();
        doneTaskInfoList_.push_back(taskInfo);
    }
    runTaskInfoList_.clear();
}

std::string WidgetContext::BuildStartCommand()
{
    WidgetCmdParameters widgetCmdParameters;
    widgetCmdParameters.uiExtensionType = "sysDialog/userAuth";
    widgetCmdParameters.useriamCmdData.widgetContextId = GetContextId();
    widgetCmdParameters.useriamCmdData.title = para_.widgetParam.title;
    widgetCmdParameters.useriamCmdData.windowModeType = WinModeType2Str(para_.widgetParam.windowMode);
    widgetCmdParameters.useriamCmdData.navigationButtonText = para_.widgetParam.navigationButtonText;
    auto it = para_.authProfileMap.find(AuthType::PIN);
    if (it != para_.authProfileMap.end()) {
        widgetCmdParameters.useriamCmdData.pinSubType = PinSubType2Str(static_cast<PinSubType>(it->second.pinSubType));
    }
    std::vector<std::string> typeList;
    for (auto &item : para_.authProfileMap) {
        auto &at = item.first;
        auto &profile = item.second;
        typeList.push_back(AuthType2Str(at));
        WidgetCommand::Cmd cmd {
            .event = "CMD_NOTIFY_AUTH_START",
            .version = WidgetClient::Instance().GetVersion(),
            .type = AuthType2Str(at)
        };
        if (at == AuthType::FINGERPRINT && !profile.sensorInfo.empty()) {
            cmd.sensorInfo = profile.sensorInfo;
        }
        cmd.remainAttempts = profile.remainTimes;
        cmd.lockoutDuration = profile.freezingTime;
        widgetCmdParameters.useriamCmdData.cmdList.push_back(cmd);
    }
    widgetCmdParameters.useriamCmdData.typeList = typeList;

    nlohmann::json root = widgetCmdParameters;
    std::string cmdData = root.dump();
    return cmdData;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
