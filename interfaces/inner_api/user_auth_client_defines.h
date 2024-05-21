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
 * @brief Type definitions used by user auth client.
 * @since 3.1
 * @version 3.2
 */

#ifndef USER_AUTH_CLIENT_DEFINES_H
#define USER_AUTH_CLIENT_DEFINES_H

#include <vector>

#include "attributes.h"
#include "iam_common_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
/**
 * @brief Remote auth parameter.
 */
struct RemoteAuthParam {
    /** verifier network id */
    std::optional<std::string> verifierNetworkId;
    /** collector network id */
    std::optional<std::string> collectorNetworkId;
    /** collector token id */
    std::optional<uint32_t> collectorTokenId;
};

/**
 * @brief Auth parameter.
 */
struct AuthParam {
    /** user id */
    int32_t userId;
    /** challenge value */
    std::vector<uint8_t> challenge;
    /** Credential type for authentication. */
    AuthType authType;
    /** Trust level of authentication result. */
    AuthTrustLevel authTrustLevel;
    /** Auth intent. */
    AuthIntent authIntent;
    /** Remote auth parameter. */
    std::optional<RemoteAuthParam> remoteAuthParam;
};

/**
 * @brief Executor property needed to get.
 */
struct GetPropertyRequest {
    /** Auth type supported by executor. */
    AuthType authType {0};
    /** The keys of attribute needed to get. */
    std::vector<Attributes::AttributeKey> keys {};
};

/**
 * @brief Executor property needed to set.
 */
struct SetPropertyRequest {
    /** Auth type supported by executor. */
    AuthType authType {0};
    /**  The executor's property mode. */
    PropertyMode mode {0};
    /** The attributes needed to set. */
    Attributes attrs {};
};

/**
 * @brief Global config type.
 */
enum GlobalConfigType : int32_t {
    /** Pin expired period */
    PIN_EXPIRED_PERIOD = 1,
};

/**
 * @brief Global config value.
 */
union GlobalConfigValue {
    /** Global config value of pin expired period.It's value should between 0 and 2^50.
      * When pinExpiredPeriod <= 0, userAuth won't check pin expired period */
    int64_t pinExpiredPeriod;
};

/**
 * @brief Global config param.
 */
struct GlobalConfigParam {
    /** Global config type. */
    GlobalConfigType type;
    /** Global config value. */
    GlobalConfigValue value;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_CLIENT_DEFINES_H