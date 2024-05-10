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

#include "remote_msg_util.h"

#include <iomanip>
#include <mutex>
#include <sstream>
#include <string>

#include "device_manager.h"

#include "device_manager_util.h"
#include "hdi_wrapper.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "parameter.h"
#include "resource_node_pool.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
const uint32_t TRUCKED_UDID_LEN = 8;
const uint32_t TRUCKED_CONTEXT_ID_LEN = 4;
} // namespace
bool RemoteMsgUtil::GetConnectionName(uint64_t contextId, std::string &connectionName)
{
    std::string udid;
    bool getLocalUdidRet = DeviceManagerUtil::GetInstance().GetLocalDeviceUdid(udid);
    IF_FALSE_LOGE_AND_RETURN_VAL(getLocalUdidRet, false);

    std::ostringstream oss;
    oss << udid.substr(0, TRUCKED_UDID_LEN) << "_Context_";
    oss << std::setw(TRUCKED_CONTEXT_ID_LEN) << std::setfill('0') << std::hex << static_cast<uint16_t>(contextId);
    connectionName = oss.str();
    return true;
}

std::string RemoteMsgUtil::GetExecutorProxyEndPointName()
{
    return "RemoteExecutorProxy";
}

std::string RemoteMsgUtil::GetExecutorStubEndPointName()
{
    return "RemoteExecutorStub";
}

std::string RemoteMsgUtil::GetRemoteServiceEndPointName()
{
    return "RemoteService";
}

std::string RemoteMsgUtil::GetRemoteCallbackEndPointName()
{
    return "RemoteCallback";
}

std::string RemoteMsgUtil::GetRemoteAuthContextEndPointName()
{
    return "RemoteAuthContext";
}

std::string RemoteMsgUtil::GetRemoteAuthInvokerContextEndPointName()
{
    return "RemoteAuthInvokerContext";
}

bool RemoteMsgUtil::EncodeQueryExecutorInfoReply(const std::vector<ExecutorInfo> &executorInfoArray,
    const std::vector<uint8_t> &signedRemoteExecutorInfo, Attributes &attr)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(executorInfoArray.size() != 0, false);

    bool setRemoteExecutorInfoRet =
        attr.SetUint8ArrayValue(Attributes::ATTR_REMOTE_EXECUTOR_INFO, signedRemoteExecutorInfo);
    IF_FALSE_LOGE_AND_RETURN_VAL(setRemoteExecutorInfoRet, false);

    return SetExecutorInfoArrayToAttributes(executorInfoArray, attr);
}

bool RemoteMsgUtil::DecodeQueryExecutorInfoReply(const Attributes &attr, std::vector<ExecutorInfo> &executorInfoArray)
{
    std::vector<uint8_t> signedRemoteExecutorInfo;
    bool getRemoteExecutorInfoRet =
        attr.GetUint8ArrayValue(Attributes::ATTR_REMOTE_EXECUTOR_INFO, signedRemoteExecutorInfo);
    IF_FALSE_LOGE_AND_RETURN_VAL(getRemoteExecutorInfoRet, false);

    return GetExecutorInfoArrayFromAttributes(attr, signedRemoteExecutorInfo, executorInfoArray);
}

bool RemoteMsgUtil::SetExecutorInfoToAttributes(const ExecutorInfo &executorInfo, Attributes &attr)
{
    bool setAuthTypeRet = attr.SetInt32Value(Attributes::ATTR_AUTH_TYPE, executorInfo.authType);
    IF_FALSE_LOGE_AND_RETURN_VAL(setAuthTypeRet, false);

    bool setExecutorRoleRet = attr.SetInt32Value(Attributes::ATTR_EXECUTOR_ROLE, executorInfo.executorRole);
    IF_FALSE_LOGE_AND_RETURN_VAL(setExecutorRoleRet, false);

    bool setExecutorSensorHintRet =
        attr.SetUint32Value(Attributes::ATTR_EXECUTOR_SENSOR_HINT, executorInfo.executorSensorHint);
    IF_FALSE_LOGE_AND_RETURN_VAL(setExecutorSensorHintRet, false);

    bool setExecutorMatcherRet = attr.SetUint32Value(Attributes::ATTR_EXECUTOR_MATCHER, executorInfo.executorMatcher);
    IF_FALSE_LOGE_AND_RETURN_VAL(setExecutorMatcherRet, false);

    bool setEslRet = attr.SetInt32Value(Attributes::ATTR_ESL, executorInfo.esl);
    IF_FALSE_LOGE_AND_RETURN_VAL(setEslRet, false);

    bool setPublicKeyRet = attr.SetUint8ArrayValue(Attributes::ATTR_PUBLIC_KEY, executorInfo.publicKey);
    IF_FALSE_LOGE_AND_RETURN_VAL(setPublicKeyRet, false);

    bool setDeviceUdidRet = attr.SetStringValue(Attributes::ATTR_DEVICE_UDID, executorInfo.deviceUdid);
    IF_FALSE_LOGE_AND_RETURN_VAL(setDeviceUdidRet, false);

    return true;
}

bool RemoteMsgUtil::GetExecutorInfoFromAttributes(const Attributes &Attr,
    std::vector<uint8_t> &signedRemoteExecutorInfo, ExecutorInfo &executorInfo)
{
    int32_t authType = 0;
    bool getAuthTypeRet = Attr.GetInt32Value(Attributes::ATTR_AUTH_TYPE, authType);
    IF_FALSE_LOGE_AND_RETURN_VAL(getAuthTypeRet, false);
    executorInfo.authType = static_cast<AuthType>(authType);

    int32_t executorRole = 0;
    bool getExecutorRoleRet = Attr.GetInt32Value(Attributes::ATTR_EXECUTOR_ROLE, executorRole);
    IF_FALSE_LOGE_AND_RETURN_VAL(getExecutorRoleRet, false);
    executorInfo.executorRole = static_cast<ExecutorRole>(executorRole);

    bool getExecutorSensorHintRet =
        Attr.GetUint32Value(Attributes::ATTR_EXECUTOR_SENSOR_HINT, executorInfo.executorSensorHint);
    IF_FALSE_LOGE_AND_RETURN_VAL(getExecutorSensorHintRet, false);

    bool getExecutorMatcherRet = Attr.GetUint32Value(Attributes::ATTR_EXECUTOR_MATCHER, executorInfo.executorMatcher);
    IF_FALSE_LOGE_AND_RETURN_VAL(getExecutorMatcherRet, false);

    int32_t esl = 0;
    bool getEslRet = Attr.GetInt32Value(Attributes::ATTR_ESL, esl);
    IF_FALSE_LOGE_AND_RETURN_VAL(getEslRet, false);
    executorInfo.esl = static_cast<ExecutorSecureLevel>(esl);

    bool getPublicKeyRet = Attr.GetUint8ArrayValue(Attributes::ATTR_PUBLIC_KEY, executorInfo.publicKey);
    IF_FALSE_LOGE_AND_RETURN_VAL(getPublicKeyRet, false);

    bool getDeviceUdidRet = Attr.GetStringValue(Attributes::ATTR_DEVICE_UDID, executorInfo.deviceUdid);
    IF_FALSE_LOGE_AND_RETURN_VAL(getDeviceUdidRet, false);

    executorInfo.signedRemoteExecutorInfo = signedRemoteExecutorInfo;
    return true;
}

bool RemoteMsgUtil::SetExecutorInfoArrayToAttributes(const std::vector<ExecutorInfo> &executorInfoArray,
    Attributes &attr)
{
    std::vector<Attributes> attributeArray;
    for (auto &executorInfo : executorInfoArray) {
        Attributes item;
        if (!SetExecutorInfoToAttributes(executorInfo, item)) {
            IAM_LOGE("SetExecutorInfoToAttributes failed");
            return false;
        }
        attributeArray.push_back(Attributes(item.Serialize()));
    }

    bool setAttributeArrayRet =
        attr.SetAttributesArrayValue(Attributes::ATTR_EXECUTOR_REGISTER_INFO_LIST, attributeArray);
    IF_FALSE_LOGE_AND_RETURN_VAL(setAttributeArrayRet, false);

    return true;
}

bool RemoteMsgUtil::GetExecutorInfoArrayFromAttributes(const Attributes &attr,
    std::vector<uint8_t> &signedRemoteExecutorInfo, std::vector<ExecutorInfo> &executorInfoArray)
{
    std::vector<Attributes> attributeArray;
    bool getExecutorInfoRet =
        attr.GetAttributesArrayValue(Attributes::ATTR_EXECUTOR_REGISTER_INFO_LIST, attributeArray);
    IF_FALSE_LOGE_AND_RETURN_VAL(getExecutorInfoRet, false);

    for (auto &item : attributeArray) {
        ExecutorInfo executorInfo;
        if (!GetExecutorInfoFromAttributes(item, signedRemoteExecutorInfo, executorInfo)) {
            IAM_LOGE("GetExecutorInfoFromAttributes failed");
            return false;
        }
        executorInfoArray.push_back(executorInfo);
    }

    return true;
}

bool RemoteMsgUtil::GetQueryExecutorInfoReply(const std::vector<int32_t> authTypes, int32_t executorRole,
    std::string remoteUdid, Attributes &attr)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, false);
    IF_FALSE_LOGE_AND_RETURN_VAL(authTypes.size() == 1, false);

    std::vector<uint8_t> signedExecutorInfo;
    int32_t hdiRet = hdi->GetSignedExecutorInfo(authTypes, executorRole, remoteUdid, signedExecutorInfo);
    IF_FALSE_LOGE_AND_RETURN_VAL(hdiRet == SUCCESS, false);

    std::string localUdid;
    bool getLocalUdidRet = DeviceManagerUtil::GetInstance().GetLocalDeviceUdid(localUdid);
    IF_FALSE_LOGE_AND_RETURN_VAL(getLocalUdidRet, false);

    std::vector<ExecutorInfo> executorInfoArray;
    ResourceNodePool::Instance().Enumerate([&](const std::weak_ptr<ResourceNode> &weakNode) {
        std::shared_ptr<ResourceNode> node = weakNode.lock();
        IF_FALSE_LOGE_AND_RETURN(node != nullptr);

        if (node->GetAuthType() != authTypes[0] || node->GetExecutorRole() != executorRole ||
            localUdid != node->GetExecutorDeviceUdid()) {
            return;
        }

        ExecutorInfo executorInfo;
        executorInfo.authType = node->GetAuthType();
        executorInfo.executorRole = node->GetExecutorRole();
        executorInfo.executorSensorHint = node->GetExecutorSensorHint();
        executorInfo.executorMatcher = node->GetExecutorMatcher();
        executorInfo.esl = node->GetExecutorEsl();
        executorInfo.publicKey = node->GetExecutorPublicKey();
        executorInfo.deviceUdid = node->GetExecutorDeviceUdid();
        executorInfoArray.push_back(executorInfo);
    });

    bool encodeQueryExecutorInfoReplyRet =
        RemoteMsgUtil::EncodeQueryExecutorInfoReply(executorInfoArray, signedExecutorInfo, attr);
    IF_FALSE_LOGE_AND_RETURN_VAL(encodeQueryExecutorInfoReplyRet, false);

    IAM_LOGI("success");
    return true;
}

bool RemoteMsgUtil::EncodeAuthParam(const AuthParamInner &authParam, Attributes &attr)
{
    bool setUserIdRet = attr.SetInt32Value(Attributes::ATTR_USER_ID, authParam.userId);
    IF_FALSE_LOGE_AND_RETURN_VAL(setUserIdRet, false);

    bool setChallengeRet = attr.SetUint8ArrayValue(Attributes::ATTR_CHALLENGE, authParam.challenge);
    IF_FALSE_LOGE_AND_RETURN_VAL(setChallengeRet, false);

    bool setAuthTypeRet = attr.SetInt32Value(Attributes::ATTR_AUTH_TYPE, authParam.authType);
    IF_FALSE_LOGE_AND_RETURN_VAL(setAuthTypeRet, false);

    bool setAuthTrustLevelRet = attr.SetInt32Value(Attributes::ATTR_AUTH_TRUST_LEVEL, authParam.authTrustLevel);
    IF_FALSE_LOGE_AND_RETURN_VAL(setAuthTrustLevelRet, false);
    return true;
}

bool RemoteMsgUtil::DecodeAuthParam(const Attributes &attr, AuthParamInner &authParam)
{
    bool getUserIdRet = attr.GetInt32Value(Attributes::ATTR_USER_ID, authParam.userId);
    IF_FALSE_LOGE_AND_RETURN_VAL(getUserIdRet, false);

    bool getChallengeRet = attr.GetUint8ArrayValue(Attributes::ATTR_CHALLENGE, authParam.challenge);
    IF_FALSE_LOGE_AND_RETURN_VAL(getChallengeRet, false);

    int32_t authType;
    bool getAuthTypeRet = attr.GetInt32Value(Attributes::ATTR_AUTH_TYPE, authType);
    IF_FALSE_LOGE_AND_RETURN_VAL(getAuthTypeRet, false);
    authParam.authType = static_cast<AuthType>(authType);

    int32_t authTrustLevel;
    bool getAuthTrustLevelRet = attr.GetInt32Value(Attributes::ATTR_AUTH_TRUST_LEVEL, authTrustLevel);
    IF_FALSE_LOGE_AND_RETURN_VAL(getAuthTrustLevelRet, false);
    authParam.authTrustLevel = static_cast<AuthTrustLevel>(authTrustLevel);

    return true;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS