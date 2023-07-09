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

#ifndef IAM_WIDGET_CONTEXT_H
#define IAM_WIDGET_CONTEXT_H

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <list>

#include "auth_common.h"
#include "ability_manager_client.h"
#include "authentication_impl.h"
#include "base_context.h"
#include "context_factory.h"
#include "in_process_call_wrapper.h"
#include "iam_callback_interface.h"
#include "widget_schedule_node.h"
#include "ui_extension_ability_connection.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class WidgetContext : public BaseContext, public WidgetScheduleNodeCallback {
public:
    WidgetContext(uint64_t contextId, const ContextFactory::AuthWidgetContextPara &para,
        std::shared_ptr<ContextCallback> callback, int32_t userId, uint32_t tokenId);
    ~WidgetContext();
    ContextType GetContextType() const override;
    uint32_t GetTokenId() const override;
    void AuthResult(int32_t resultCode, int32_t at, const Attributes &finalResult,
        const std::shared_ptr<Context> &task);
    std::shared_ptr<Context> GetTaskFromIamcallback(const std::shared_ptr<IamCallbackInterface> &iamCallback);

    // WidgetScheduleNodeCallback
    void LaunchWidget() override;
    void ExecuteAuthList(const std::set<AuthType> &authTypeList) override;
    void EndAuthAsCancel() override;
    void EndAuthAsNaviPin() override;
    void StopAuthList(const std::vector<AuthType> &authTypeList) override;
    void SuccessAuth(AuthType authType) override;
    void SetTokenIdByWidget(uint32_t tokenId);

protected:
    // BaseContext
    bool OnStart() override;
    void OnResult(int32_t resultCode, const std::shared_ptr<Attributes> &scheduleResultAttr) override;
    bool OnStop() override;

private:
    std::shared_ptr<Context> BuildTask(const std::vector<uint8_t> &challenge,
        AuthType authType, AuthTrustLevel authTrustLevel);
    bool BuildSchedule();
    bool ConnectExtension();
    int32_t ConnectExtensionAbility(const AAFwk::Want &want, const std::string commandStr);
    bool DisconnectExtension();
    void End(const ResultCode &resultCode);
    std::shared_ptr<ContextCallback> GetAuthContextCallback(AuthType authType,
        AuthTrustLevel authTrustLevel, std::shared_ptr<IamCallbackInterface> &callback);
    bool TaskRun2Done(const std::shared_ptr<Context> &task);
    void StopAllRunTask();
    std::string BuildStartCommand();

    struct TaskInfo {
        AuthType authType;
        std::shared_ptr<Context> task;
    };

    ContextFactory::AuthWidgetContextPara para_;
    std::shared_ptr<WidgetScheduleNode> schedule_ {nullptr};
    int32_t userId_;
    uint32_t tokenId_;
    sptr<AAFwk::IAbilityConnection> abilityConnection_ {nullptr};
    std::recursive_mutex mutex_;
    std::map<std::shared_ptr<IamCallbackInterface>, std::shared_ptr<Context>> iam2TaskMap_;
    std::list<TaskInfo> runTaskInfoList_;
    std::list<TaskInfo> doneTaskInfoList_;
    sptr<UIExtensionAbilityConnection> connection_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_WIDGET_CONTEXT_H
