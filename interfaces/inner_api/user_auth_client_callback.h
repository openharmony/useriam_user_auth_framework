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
 * @file user_auth_client_callback.h
 *
 * @brief Callback definitions returned by user auth client.
 * @since 3.1
 * @version 3.2
 */

#ifndef USER_AUTH_CLIENT_CALLBACK_H
#define USER_AUTH_CLIENT_CALLBACK_H

#include "attributes.h"
#include "iremote_broker.h"
#include "user_auth_client_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class AuthenticationCallback {
public:
    /**
     * @brief The callback return authenticate acquire information.
     *
     * @param module Module of current acquire info.
     * @param acquireInfo Acquire info needed to be pass in.
     * @param extraInfo Other related information about authentication.
     */
    virtual void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) = 0;

    /**
     * @brief The callback return authenticate result.
     *
     * @param result The result success or error code{@link ResultCode}.
     * @param extraInfo Other related information about authentication.
     */
    virtual void OnResult(int32_t result, const Attributes &extraInfo) = 0;
};

class IdentificationCallback {
public:
    /**
     * @brief The callback return identification acquire information.
     *
     * @param module Module of current acquire info.
     * @param acquireInfo Acquire info needed to be pass in.
     * @param extraInfo Other related information about identification.
     */
    virtual void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) = 0;

    /**
     * @brief The callback return identification result.
     *
     * @param result The result success or error code{@link ResultCode}.
     * @param extraInfo Other related information about identification.
     */
    virtual void OnResult(int32_t result, const Attributes &extraInfo) = 0;
};

class GetPropCallback {
public:
    /**
     * @brief The callback return get property result.
     *
     * @param result The result success or error code{@link ResultCode}.
     * @param extraInfo Other related information about get property.
     */
    virtual void OnResult(int32_t result, const Attributes &extraInfo) = 0;
};

class SetPropCallback {
public:
    /**
     * @brief The callback return set property result.
     *
     * @param result The result success or error code{@link ResultCode}.
     * @param extraInfo Other related information about set property.
     */
    virtual void OnResult(int32_t result, const Attributes &extraInfo) = 0;
};

class AuthEventListenerInterface : public IRemoteBroker {
public:
    /**
     * @brief Notify the event of authencation success.
     *
     * @param userId The id of user who initiates authentication.
     * @param authtype The authentication auth type{@link AuthType}.
     * @param callerType The caller type who initiates authentication.
     * @param callerName The caller name who initiates authentication.
     */
    virtual void OnNotifyAuthSuccessEvent(int32_t userId, AuthType authtype, int32_t callerType,
        std::string &callerName) = 0;
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.UserIam.UserAuth.EventListenerCallback");
};

class PrepareRemoteAuthCallback {
public:
    /**
     * @brief The callback return prepare remote auth result.
     *
     * @param result The result success or error code{@link ResultCode}.
     */
    virtual void OnResult(int32_t result) = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_CLIENT_CALLBACK_H