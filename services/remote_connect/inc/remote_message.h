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

#ifndef REMOTE_MSG_COMMON_H
#define REMOTE_MSG_COMMON_H

namespace OHOS {
namespace UserIam {
namespace UserAuth {
enum MessageType {
    // collector remoteAuthService -> verifier remoteAuthService
    START_REMOTE_AUTH = 1,

    // verifier remoteAuthService callback -> collector remoteAuthInvokerContext
    SEND_REMOTE_AUTH_TIP = 2,
    SEND_REMOTE_AUTH_RESULT = 3,

    // verifier remoteAuthInvokerContext -> collector remoteAuthService
    QUERY_EXECUTOR_INFO = 4,

    // verifier executor proxy -> collector remoteAuthService
    BEGIN_EXECUTE = 5,
    END_EXECUTE = 6,

    // verifier executor proxy -> executor stub
    SEND_DATA_TO_EXECUTOR = 7,

    // collector executor stub -> verifier executor proxy
    EXECUTOR_FINISH = 8,
    EXECUTOR_SEND_DATA = 9,

    // keep alive
    KEEP_ALIVE = 10,
};

const inline char *EXECUTOR_PROXY_ENDPOINT_NAME = "RemoteExecutorProxy";
const inline char *EXECUTOR_STUB_ENDPOINT_NAME = "RemoteExecutorStub";
const inline char *REMOTE_SERVICE_ENDPOINT_NAME = "RemoteService";
const inline char *REMOTE_CALLBACK_ENDPOINT_NAME = "RemoteCallback";
const inline char *REMOTE_AUTH_CONTEXT_ENDPOINT_NAME = "RemoteAuthContext";
const inline char *REMOTE_AUTH_INVOKER_CONTEXT_ENDPOINT_NAME = "RemoteAuthInvokerContext";
const inline char *CLIENT_SOCKET_ENDPOINT_NAME = "ClientSocket";
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // REMOTE_MSG_COMMON_H