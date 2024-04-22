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

/**
 * @file co_auth_client_defines.h
 *
 * @brief Type definitions used by coAuth client.
 * @since 3.1
 * @version 3.2
 */

#ifndef CO_AUTH_CLIENT_DEFINES_H
#define CO_AUTH_CLIENT_DEFINES_H

#include <vector>

#include "attributes.h"
#include "iam_common_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
/**
 * @brief Infomation used to describe an Executor.
 */
struct ExecutorInfo {
    /** Authentication type supported by executor. */
    AuthType authType {0};
    /** Executor role. */
    ExecutorRole executorRole {0};
    /** Unique index of executor within each authType. */
    uint32_t executorSensorHint {0};
    /** Sensor or algorithm type supported by executor. */
    uint32_t executorMatcher {0};
    /** Executor secure level. */
    ExecutorSecureLevel esl {0};
    /** Max template acl. */
    uint32_t maxTemplateAcl {0};
    /** Used to verify the result issued by the authenticator. */
    std::vector<uint8_t> publicKey {};
    /**< Device udid. */
    std::string deviceUdid;
    /**< signed remote executor info. */
    std::vector<uint8_t> signedRemoteExecutorInfo;
};

class AuthMessage {
public:
    /**
     * @brief Function of type conversion.
     *
     * @param msg Incoming vector<uint8_t> type.
     * @return Return shared_ptr<AuthMessage>.
     */
    static std::shared_ptr<AuthMessage> As(const std::vector<uint8_t> &msg);
};

class ExecutorMessenger {
public:
    /**
     * @brief Called by the executor, send authentication data to resource pool.
     *
     * @param scheduleId Specify the current schedule.
     * @param dstRole Destination executor role.
     * @param msg Authentication message.
     * @return Return send data success or not(0:success; other:failed).
     */
    virtual int32_t SendData(uint64_t scheduleId, ExecutorRole dstRole, const std::shared_ptr<AuthMessage> &msg) = 0;

    /**
     * @brief Called by the executor, send finish data to resource pool.
     *
     * @param scheduleId Specify the current schedule.
     * @param resultCode Authentication result code.
     * @param finalResult Authentication final result.
     * @return Return finish success or not(0:success; other:failed).
     */
    virtual int32_t Finish(uint64_t scheduleId, int32_t resultCode, const Attributes &finalResult) = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // CO_AUTH_CLIENT_DEFINES_H