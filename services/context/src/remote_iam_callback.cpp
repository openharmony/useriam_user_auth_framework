/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "remote_iam_callback.h"

#include "iam_check.h"
#include "iam_ptr.h"
#include "remote_connect_manager.h"
#include "remote_msg_util.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
RemoteIamCallback::RemoteIamCallback(std::string &connectionName) : connectionName_(connectionName)
{
}

RemoteIamCallback::~RemoteIamCallback()
{
}

bool RemoteIamCallback::Init()
{
    localEndPointName_ = RemoteMsgUtil::GetRemoteCallbackEndPointName();
    return true;
}

void RemoteIamCallback::OnResult(int32_t result, const Attributes &extraInfo)
{
    IAM_LOGI("result: %{public}d", result);

    std::shared_ptr<Attributes> request = Common::MakeShared<Attributes>(extraInfo.Serialize());
    IF_FALSE_LOGE_AND_RETURN(request != nullptr);

    bool setMsgTypeRet = request->SetInt32Value(Attributes::ATTR_MSG_TYPE, SEND_REMOTE_AUTH_RESULT);
    IF_FALSE_LOGE_AND_RETURN(setMsgTypeRet);

    bool setResultRet = request->SetInt32Value(Attributes::ATTR_RESULT, result);
    IF_FALSE_LOGE_AND_RETURN(setResultRet);

    MsgCallback msgCallback = [](const std::shared_ptr<Attributes> &) { IAM_LOGI("message sent"); };

    ResultCode sendMsgRet = RemoteConnectionManager::GetInstance().SendMessage(connectionName_, localEndPointName_,
        RemoteMsgUtil::GetRemoteAuthInvokerContextEndPointName(), request, msgCallback);
    IF_FALSE_LOGE_AND_RETURN(sendMsgRet == ResultCode::SUCCESS);

    IAM_LOGI("success");
}

void RemoteIamCallback::OnAcquireInfo(int32_t module, int32_t acquireInfo, const Attributes &extraInfo)
{
    IAM_LOGI("module: %{public}d, acquireInfo: %{public}d", module, acquireInfo);

    std::shared_ptr<Attributes> request = Common::MakeShared<Attributes>(extraInfo.Serialize());
    IF_FALSE_LOGE_AND_RETURN(request != nullptr);

    bool setMsgTypeRet = request->SetInt32Value(Attributes::ATTR_MSG_TYPE, SEND_REMOTE_AUTH_TIP);
    IF_FALSE_LOGE_AND_RETURN(setMsgTypeRet);

    bool setModuleRet = request->SetInt32Value(Attributes::ATTR_DEST_ROLE, module);
    IF_FALSE_LOGE_AND_RETURN(setModuleRet);

    bool setAcquireInfoRet = request->SetInt32Value(Attributes::ATTR_TIP_INFO, acquireInfo);
    IF_FALSE_LOGE_AND_RETURN(setAcquireInfoRet);

    MsgCallback msgCallback = [](const std::shared_ptr<Attributes> &) { IAM_LOGI("message sent"); };

    ResultCode sendMsgRet = RemoteConnectionManager::GetInstance().SendMessage(connectionName_, localEndPointName_,
        RemoteMsgUtil::GetRemoteAuthInvokerContextEndPointName(), request, msgCallback);
    IF_FALSE_LOGE_AND_RETURN(sendMsgRet == ResultCode::SUCCESS);

    IAM_LOGI("success");
}

sptr<IRemoteObject> RemoteIamCallback::AsObject()
{
    return nullptr;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS