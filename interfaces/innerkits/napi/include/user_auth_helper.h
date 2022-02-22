/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#ifndef FACERECOGNITION_PIN_AUTH_HELPER_H
#define FACERECOGNITION_PIN_AUTH_HELPER_H

#include "napi/native_api.h"
#include "napi/native_common.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
/**
 * @brief Napi initialization
 *
 * @param env
 * @param exports
 */
void Init(napi_env env, napi_value exports);

/**
 * @brief Get the Ctor object
 *
 * @param env
 * @return napi_value UserAuth Instance
 */
napi_value GetCtor(napi_env env);

/**
 * @brief Construction method
 *
 * @param env
 * @param info
 * @return napi_value UserAuth Instance
 */
napi_value Constructor(napi_env env, napi_callback_info info);

/**
 * @brief Get the Ctor object for API6
 *
 * @param env
 * @return napi_value UserAuth Instance
 */
napi_value GetCtorForAPI6(napi_env env);

/**
 * @brief Construction method for API6
 *
 * @param env
 * @param info
 * @return napi_value UserAuth Instance
 */
napi_value ConstructorForAPI6(napi_env env, napi_callback_info info);

/**
 * @brief Instance passed to context
 *
 * @param env
 * @param info
 * @return napi_value Instance
 */
napi_value UserAuthServiceConstructor(napi_env env, napi_callback_info info);

/**
 * @brief Get the Version object
 *
 * @param env
 * @param info
 * @return napi_value Specific version number results
 */
napi_value GetVersion(napi_env env, napi_callback_info info);

/**
 * @brief Get the Availabe Status object
 *
 * @param env
 * @param info
 * @return napi_value Verify that the certification capability is available
 */
napi_value GetAvailableStatus(napi_env env, napi_callback_info info);

/**
 * @brief Get the Property object
 *
 * @param env
 * @param info
 * @return napi_value It supports querying subclasses / remaining authentication times / freezing time
 */
napi_value GetProperty(napi_env env, napi_callback_info info);

/**
 * @brief Set the Property object
 *
 * @param env
 * @param info
 * @return napi_value Set properties: can be used to initialize algorithms
 */
napi_value SetProperty(napi_env env, napi_callback_info info);

/**
 * @brief user authentication
 *
 * @param env
 * @param info
 * @return napi_value Enter the challenge value, authentication method, trust level and callback, and return the result
 * and acquireinfo through the callback
 */
napi_value Auth(napi_env env, napi_callback_info info);

/**
 * @brief Execute authentication
 *
 * @param env
 * @param info
 * @return Returns the result of successful authentication
 */
napi_value Execute(napi_env env, napi_callback_info info);

/**
 * @brief user authentication
 *
 * @param env
 * @param info
 * @return napi_value Pass in the user ID, challenge value, authentication method, trust level and callback, and return
 * the result acquireinfo through the callback
 */
napi_value AuthUser(napi_env env, napi_callback_info info);

/**
 * @brief Cancel authentication
 *
 * @param env
 * @param info
 * @return napi_value success or fail
 */
napi_value CancelAuth(napi_env env, napi_callback_info info);
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
#endif // FACERECOGNITION_PIN_AUTH_HELPER_H
