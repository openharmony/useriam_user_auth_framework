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

#ifndef IAM_WIDGET_CONTEXT_H
#define IAM_WIDGET_CONTEXT_H

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <list>
#include <vector>

#include "auth_common.h"
#include "extension_manager_client.h"
#include "authentication_impl.h"
#include "base_context.h"
#include "context.h"
#include "context_appstate_observer.h"
#include "context_death_recipient.h"
#include "context_factory.h"
#include "in_process_call_wrapper.h"
#include "iam_callback_interface.h"
#include "nocopyable.h"
#include "widget_schedule_node.h"
#include "ui_extension_ability_connection.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace OHOS::AppExecFwk;
class WidgetContext : public WidgetScheduleNodeCallback,
                      public Context,
                      public std::enable_shared_from_this<WidgetContext>,
                      public ContextDeathRecipientManager,
                      public ContextAppStateObserverManager,
                      public NoCopyable {
public:
    WidgetContext(uint64_t contextId, const ContextFactory::AuthWidgetContextPara &para,
        std::shared_ptr<ContextCallback> callback);
    ~WidgetContext() override;

    // Context API
    bool Start() override;
    bool Stop() override;
    uint64_t GetContextId() const override;
    ContextType GetContextType() const override;
    std::shared_ptr<ScheduleNode> GetScheduleNode(uint64_t scheduleId) const override;
    uint32_t GetTokenId() const override;
    int32_t GetLatestError() const override;

    // WidgetScheduleNodeCallback API
    bool LaunchWidget() override;
    void ExecuteAuthList(const std::set<AuthType> &authTypeList, bool endAfterFirstFail) override;
    void EndAuthAsCancel() override;
    void EndAuthAsNaviPin() override;
    void EndAuthAsWidgetParaInvalid() override;
    void StopAuthList(const std::vector<AuthType> &authTypeList) override;
    void SuccessAuth(AuthType authType) override;

    void AuthResult(int32_t resultCode, int32_t authType, const Attributes &finalResult);
    void AuthTipInfo(int32_t tipInfo, int32_t authType, const Attributes &extraInfo);
protected:
    virtual bool OnStart();
    virtual void OnResult(int32_t resultCode, const std::shared_ptr<Attributes> &scheduleResultAttr);
    virtual bool OnStop();

private:
    void SetLatestError(int32_t error) override;
    std::shared_ptr<Context> BuildTask(const std::vector<uint8_t> &challenge,
        AuthType authType, AuthTrustLevel authTrustLevel, bool endAfterFirstFail);
    bool BuildSchedule();
    bool ConnectExtension();
    int32_t ConnectExtensionAbility(const AAFwk::Want &want, const std::string commandStr);
    bool DisconnectExtension();
    void End(const ResultCode &resultCode);
    std::shared_ptr<ContextCallback> GetAuthContextCallback(AuthType authType, AuthTrustLevel authTrustLevel,
        sptr<IamCallbackInterface> &callback);
    void StopAllRunTask();
    std::string BuildStartCommand();
    std::shared_ptr<UserIam::UserAuth::IamHitraceHelper> connectAbilityHitrace_ {nullptr};

private:
    struct TaskInfo {
        AuthType authType {0};
        std::shared_ptr<Context> task {nullptr};
    };

    struct WidgetAuthResultInfo {
        std::vector<uint8_t> token {};
        AuthType authType { 0 };
        uint64_t credentialDigest;
        uint16_t credentialCount;
        int64_t pinExpiredInfo;
    };

    uint64_t contextId_ {0};
    std::string description_ {""};
    std::shared_ptr<ContextCallback> callerCallback_ {nullptr};
    bool hasStarted_ {false};

    int32_t latestError_ {ResultCode::GENERAL_ERROR};
    ContextFactory::AuthWidgetContextPara para_ {};
    std::shared_ptr<WidgetScheduleNode> schedule_ {nullptr};
    std::recursive_mutex mutex_;
    std::list<TaskInfo> runTaskInfoList_;
    sptr<UIExtensionAbilityConnection> connection_ {nullptr};
    WidgetAuthResultInfo authResultInfo_ {};
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_WIDGET_CONTEXT_H
