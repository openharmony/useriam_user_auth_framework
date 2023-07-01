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

#ifndef USER_IDM_INTERFACE_IPC_INTERFACE_CODE_H
#define USER_IDM_INTERFACE_IPC_INTERFACE_CODE_H

/* SAID: 931 */
namespace OHOS {
namespace UserIam {
namespace UserAuth {
enum class UserIdmInterfaceCode {
    USER_IDM_OPEN_SESSION = 0,
    USER_IDM_CLOSE_SESSION,
    USER_IDM_GET_CRED_INFO,
    USER_IDM_GET_SEC_INFO,
    USER_IDM_ADD_CREDENTIAL,
    USER_IDM_UPDATE_CREDENTIAL,
    USER_IDM_CANCEL,
    USER_IDM_ENFORCE_DEL_USER,
    USER_IDM_DEL_USER,
    USER_IDM_DEL_CRED,
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_IDM_INTERFACE_IPC_INTERFACE_CODE_H