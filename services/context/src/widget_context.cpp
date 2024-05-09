/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include "context_death_recipient.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "iam_time.h"
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
#include "hisysevent_adapter.h"
#include "system_ability_definition.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
constexpr int32_t DEFAULT_VALUE = -1;
const std::string UI_EXTENSION_TYPE_SET = "sysDialog/userAuth";

WidgetContext::WidgetContext(uint64_t contextId, const ContextFactory::AuthWidgetContextPara &para,
    std::shared_ptr<ContextCallback> callback)
    : contextId_(contextId), description_("UserAuthWidget"), callerCallback_(callback), hasStarted_(false),
    latestError_(ResultCode::GENERAL_ERROR), para_(para), schedule_(nullptr), connection_(nullptr)
{
    AddDeathRecipient(callerCallback_, contextId_);
    SubscribeAppState(callerCallback_, contextId_);
}

WidgetContext::~WidgetContext()
{
    IAM_LOGI("release WidgetContext");
    RemoveDeathRecipient(callerCallback_);
    UnSubscribeAppState();
}

bool WidgetContext::Start()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("%{public}s start", description_.c_str());
    if (hasStarted_) {
        IAM_LOGI("%{public}s context has started, cannot start again", description_.c_str());
        return false;
    }
    hasStarted_ = true;
    return OnStart();
}

bool WidgetContext::Stop()
{
    IAM_LOGI("%{public}s start", description_.c_str());
    return OnStop();
}

uint64_t WidgetContext::GetContextId() const
{
    return contextId_;
}

ContextType WidgetContext::GetContextType() const
{
    return WIDGET_AUTH_CONTEXT;
}

std::shared_ptr<ScheduleNode> WidgetContext::GetScheduleNode(uint64_t scheduleId) const
{
    return nullptr;
}

uint32_t WidgetContext::GetTokenId() const
{
    return para_.tokenId;
}

int32_t WidgetContext::GetLatestError() const
{
    return latestError_;
}

void WidgetContext::SetLatestError(int32_t error)
{
    if (error != ResultCode::SUCCESS) {
        latestError_ = error;
    }
}

bool WidgetContext::BuildSchedule()
{
    schedule_ = Common::MakeShared<WidgetScheduleNodeImpl>();
    IF_FALSE_LOGE_AND_RETURN_VAL(schedule_ != nullptr, false);
    schedule_->SetCallback(shared_from_this());
    return true;
}

std::shared_ptr<ContextCallback> WidgetContext::GetAuthContextCallback(AuthType authType,
    AuthTrustLevel authTrustLevel, sptr<IamCallbackInterface> &iamCallback)
{
    auto widgetCallback = ContextCallback::NewInstance(iamCallback, TRACE_AUTH_USER_SECURITY);
    if (widgetCallback == nullptr) {
        IAM_LOGE("failed to construct context callback");
        Attributes extraInfo;
        iamCallback->OnResult(ResultCode::GENERAL_ERROR, extraInfo);
        return nullptr;
    }
    widgetCallback->SetTraceCallerName(para_.callerName);
    widgetCallback->SetTraceCallerType(para_.callerType);
    widgetCallback->SetTraceRequestContextId(contextId_);
    widgetCallback->SetTraceAuthTrustLevel(authTrustLevel);
    widgetCallback->SetTraceAuthType(authType);
    return widgetCallback;
}

std::shared_ptr<Context> WidgetContext::BuildTask(const std::vector<uint8_t> &challenge,
    AuthType authType, AuthTrustLevel authTrustLevel, bool endAfterFirstFail)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(callerCallback_ != nullptr, nullptr);
    auto userId = para_.userId;
    auto tokenId = WidgetClient::Instance().GetAuthTokenId();
    IAM_LOGI("Real userId: %{public}d, Real tokenId: %{public}u", userId, tokenId);
    sptr<IamCallbackInterface> iamCallback(new (std::nothrow) WidgetContextCallbackImpl(weak_from_this(),
        static_cast<int32_t>(authType)));
    IF_FALSE_LOGE_AND_RETURN_VAL(iamCallback != nullptr, nullptr);
    auto widgetCallback = GetAuthContextCallback(authType, authTrustLevel, iamCallback);
    IF_FALSE_LOGE_AND_RETURN_VAL(widgetCallback != nullptr, nullptr);

    Authentication::AuthenticationPara para = {};
    para.tokenId = tokenId;
    para.userId = userId;
    para.authType = authType;
    para.atl = authTrustLevel;
    para.challenge = challenge;
    para.endAfterFirstFail = endAfterFirstFail;
    para.callerName = para_.callerName;
    para.sdkVersion = para_.sdkVersion;
    para.authIntent = AuthIntent::DEFAULT;
    auto context = ContextFactory::CreateSimpleAuthContext(para, widgetCallback);
    if (context == nullptr || !ContextPool::Instance().Insert(context)) {
        IAM_LOGE("failed to insert context");
        Attributes extraInfo;
        widgetCallback->OnResult(ResultCode::GENERAL_ERROR, extraInfo);
        return nullptr;
    }
    widgetCallback->SetTraceAuthContextId(context->GetContextId());
    widgetCallback->SetCleaner(ContextHelper::Cleaner(context));
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return context;
}

bool WidgetContext::OnStart()
{
    IAM_LOGI("%{public}s start", description_.c_str());
    if (!BuildSchedule()) {
        IAM_LOGE("failed to create widget schedule");
        return false;
    }
    WidgetClient::Instance().SetWidgetContextId(GetContextId());
    WidgetClient::Instance().SetWidgetParam(para_.widgetParam);
    WidgetClient::Instance().SetAuthTypeList(para_.authTypeList);
    WidgetClient::Instance().SetWidgetSchedule(schedule_);
    WidgetClient::Instance().SetChallenge(para_.challenge);
    WidgetClient::Instance().SetCallingBundleName(para_.callingBundleName);
    schedule_->StartSchedule();

    IAM_LOGI("WidgetContext start success.");
    return true;
}

void WidgetContext::OnResult(int32_t resultCode, const std::shared_ptr<Attributes> &scheduleResultAttr)
{
    IAM_LOGI("%{public}s receive result code %{public}d", description_.c_str(), resultCode);
}

bool WidgetContext::OnStop()
{
    // response app.cancel()
    IAM_LOGI("%{public}s start", description_.c_str());
    End(ResultCode::CANCELED);
    return true;
}

void WidgetContext::AuthResult(int32_t resultCode, int32_t authType, const Attributes &finalResult)
{
    IAM_LOGI("recv task result: %{public}d, authType: %{public}d", resultCode, authType);
    int32_t remainTimes = -1;
    int32_t freezingTime = -1;
    if (!finalResult.GetInt32Value(Attributes::ATTR_REMAIN_TIMES, remainTimes)) {
        IAM_LOGI("get remainTimes failed.");
    }
    if (!finalResult.GetInt32Value(Attributes::ATTR_FREEZING_TIME, freezingTime)) {
        IAM_LOGI("get freezingTime failed.");
    }
    AuthType authTypeTmp = static_cast<AuthType>(authType);
    WidgetClient::Instance().ReportWidgetResult(resultCode, authTypeTmp, freezingTime, remainTimes);
    IF_FALSE_LOGE_AND_RETURN(schedule_ != nullptr);
    IF_FALSE_LOGE_AND_RETURN(callerCallback_ != nullptr);
    callerCallback_->SetTraceAuthType(authTypeTmp);
    IAM_LOGI("call schedule:");
    if (resultCode == ResultCode::SUCCESS) {
        finalResult.GetUint8ArrayValue(Attributes::ATTR_SIGNATURE, authResultInfo_.token);
        finalResult.GetUint64Value(Attributes::ATTR_CREDENTIAL_DIGEST, authResultInfo_.credentialDigest);
        finalResult.GetUint16Value(Attributes::ATTR_CREDENTIAL_COUNT, authResultInfo_.credentialCount);
        authResultInfo_.authType = authTypeTmp;
        schedule_->SuccessAuth(authTypeTmp);
    } else {
        // failed
        SetLatestError(resultCode);
        schedule_->StopAuthList({authTypeTmp});
    }
}

void WidgetContext::AuthTipInfo(int32_t tipType, int32_t authType, const Attributes &extraInfo)
{
    IAM_LOGI("recv tip: %{public}d, authType: %{public}d", tipType, authType);
    std::vector<uint8_t> tipInfo;
    bool getTipInfoRet = extraInfo.GetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, tipInfo);
    IF_FALSE_LOGE_AND_RETURN(getTipInfoRet);
    WidgetClient::Instance().ReportWidgetTip(tipType, static_cast<AuthType>(authType), tipInfo);
}

// WidgetScheduleNodeCallback
bool WidgetContext::LaunchWidget()
{
    IAM_LOGI("launch widget");
    if (!ConnectExtension()) {
        IAM_LOGE("failed to launch widget.");
        return false;
    }
    return true;
}

void WidgetContext::ExecuteAuthList(const std::set<AuthType> &authTypeList, bool endAfterFirstFail)
{
    IAM_LOGI("execute auth list");
    // create task, and start it
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    for (auto &authType : authTypeList) {
        auto task = BuildTask(para_.challenge, authType, para_.atl, endAfterFirstFail);
        if (task == nullptr) {
            IAM_LOGE("failed to create task, authType: %{public}s", AuthType2Str(authType).c_str());
            continue;
        }
        if (!task->Start()) {
            IAM_LOGE("BeginAuthentication failed");
            static const int32_t INVALID_VAL = -1;
            WidgetClient::Instance().ReportWidgetResult(task->GetLatestError(), authType, INVALID_VAL, INVALID_VAL);
            return;
        }
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

void WidgetContext::EndAuthAsWidgetParaInvalid()
{
    IAM_LOGI("end auth as widget para invalid");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    End(ResultCode::INVALID_PARAMETERS);
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
            if (it->task == nullptr) {
                IAM_LOGE("task is nullptr");
                return;
            }
            it->task->Stop();
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

int32_t WidgetContext::ConnectExtensionAbility(const AAFwk::Want &want, const std::string commandStr)
{
    IAM_LOGI("ConnectExtensionAbility start");
    if (connection_ != nullptr) {
        IAM_LOGE("invalid connection_");
        return ERR_INVALID_OPERATION;
    }
    connection_ = sptr<UIExtensionAbilityConnection>(new (std::nothrow) UIExtensionAbilityConnection(commandStr));
    if (connection_ == nullptr) {
        IAM_LOGE("new connection error.");
        return ERR_NO_MEMORY;
    }

    std::string identity = IPCSkeleton::ResetCallingIdentity();
    auto ret = AAFwk::ExtensionManagerClient::GetInstance().ConnectServiceExtensionAbility(want, connection_, nullptr,
        DEFAULT_VALUE);
    IPCSkeleton::SetCallingIdentity(identity);
    IAM_LOGI("ConnectExtensionAbility errCode=%{public}d", ret);
    return ret;
}

bool WidgetContext::ConnectExtension()
{
    std::string tmp = BuildStartCommand();
    IAM_LOGI("start command: %{public}s", tmp.c_str());

    AAFwk::Want want;
    std::string bundleName = "com.ohos.systemui";
    std::string abilityName = "com.ohos.systemui.dialog";
    want.SetElementName(bundleName, abilityName);
    auto ret = ConnectExtensionAbility(want, tmp);
    if (ret != ERR_OK) {
        UserIam::UserAuth::ReportSystemFault(Common::GetNowTimeString(), "userauthservice");
        IAM_LOGE("ConnectExtensionAbility failed.");
        return false;
    }
    return true;
}

bool WidgetContext::DisconnectExtension()
{
    if (connection_ == nullptr) {
        IAM_LOGE("invalid connection handle");
        return false;
    }
    ErrCode ret = AAFwk::ExtensionManagerClient::GetInstance().DisconnectAbility(connection_);
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
    if (resultCode != ResultCode::SUCCESS) {
        IAM_LOGI("Try to disconnect extesnion");
        if (!DisconnectExtension()) {
            IAM_LOGE("failed to release launch widget.");
        }
    }
    IF_FALSE_LOGE_AND_RETURN(callerCallback_ != nullptr);
    Attributes attr;
    if (resultCode == ResultCode::SUCCESS) {
        if (!attr.SetInt32Value(Attributes::ATTR_AUTH_TYPE, authResultInfo_.authType)) {
            IAM_LOGE("set auth type failed.");
            callerCallback_->OnResult(ResultCode::GENERAL_ERROR, attr);
            return;
        }
        if (authResultInfo_.token.size() > 0) {
            if (!attr.SetUint8ArrayValue(Attributes::ATTR_SIGNATURE, authResultInfo_.token)) {
                IAM_LOGE("set signature token failed.");
                callerCallback_->OnResult(ResultCode::GENERAL_ERROR, attr);
                return;
            }
        }
        if (!attr.SetUint64Value(Attributes::ATTR_CREDENTIAL_DIGEST, authResultInfo_.credentialDigest)) {
            IAM_LOGE("set credential digest failed.");
            callerCallback_->OnResult(ResultCode::GENERAL_ERROR, attr);
            return;
        }
        if (!attr.SetUint16Value(Attributes::ATTR_CREDENTIAL_COUNT, authResultInfo_.credentialCount)) {
            IAM_LOGE("set credential count failed.");
            callerCallback_->OnResult(ResultCode::GENERAL_ERROR, attr);
            return;
        }
    }
    callerCallback_->OnResult(resultCode, attr);
}

void WidgetContext::StopAllRunTask()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    for (auto &taskInfo : runTaskInfoList_) {
        IAM_LOGI("stop task");
        taskInfo.task->Stop();
    }
    runTaskInfoList_.clear();
}

std::string WidgetContext::BuildStartCommand()
{
    WidgetCmdParameters widgetCmdParameters;
    widgetCmdParameters.uiExtensionType = UI_EXTENSION_TYPE_SET;
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
            .event = CMD_NOTIFY_AUTH_START,
            .version = NOTICE_VERSION_STR,
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
