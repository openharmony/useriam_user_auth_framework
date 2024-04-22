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

#ifndef USER_AUTH_INTERFACE_IPC_INTERFACE_CODE_H
#define USER_AUTH_INTERFACE_IPC_INTERFACE_CODE_H

/* SAID: 921 */
namespace OHOS {
namespace UserIam {
namespace UserAuth {
enum UserAuthInterfaceCode : uint32_t {
    USER_AUTH_GET_AVAILABLE_STATUS = 0,
    USER_AUTH_GET_PROPERTY,
    USER_AUTH_SET_PROPERTY,
    USER_AUTH_AUTH,
    USER_AUTH_AUTH_USER,
    USER_AUTH_CANCEL_AUTH,
    USER_AUTH_GET_VERSION,
    USER_AUTH_ON_RESULT,
    USER_AUTH_GET_EX_PROP,
    USER_AUTH_SET_EX_PROP,
    USER_AUTH_ACQUIRE_INFO,
    USER_AUTH_IDENTIFY,
    USER_AUTH_CANCEL_IDENTIFY,
    USER_AUTH_ON_IDENTIFY_RESULT,
    USER_AUTH_AUTH_WIDGET,
    USER_AUTH_NOTICE,
    USER_AUTH_ON_SEND_COMMAND,
    USER_AUTH_REG_WIDGET_CB,
    USER_AUTH_GET_ENROLLED_STATE,
    USER_AUTH_REG_EVENT_LISTENER,
    USER_AUTH_UNREG_EVENT_LISTENER,
    USER_AUTH_EVENT_LISTENER_NOTIFY,
    USER_AUTH_SET_CLOBAL_CONFIG_PARAM,
    USER_AUTH_PREPARE_REMOTE_AUTH,
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_INTERFACE_IPC_INTERFACE_CODE_H