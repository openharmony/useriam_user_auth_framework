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

#ifndef IUSERIDM_H
#define IUSERIDM_H

#include "iuseridm_callback.h"

namespace OHOS {
namespace UserIAM {
namespace UserIDM {
class IUserIDM : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.useridm.IUserIDM");

    /*
     * start an IDM operation to obtain challenge value, a challenge value of 0 indicates that opensession failed.
     *
     * return challenge value.
     */
    virtual uint64_t OpenSession() = 0;

    /*
     * end an IDM operation.
     */
    virtual void CloseSession() = 0;

    /*
     * get authentication information.
     *
     * param authType credential type.
     * param callback returns all registered credential information of this type for the specific user.
     */
    virtual int32_t GetAuthInfo(AuthType authType, const sptr<IGetInfoCallback>& callback) = 0;

    /*
     * get authentication information.
     *
     * param userId current user id.
     * param authType credential type.
     * param callback returns all registered credential information of this type for the specific user.
     */
    virtual int32_t GetAuthInfo(int32_t userId, AuthType authType, const sptr<IGetInfoCallback>& callback) = 0;

    /*
     * get user security ID.
     *
     * param userId current user id.
     * param callback returns all registered security information for the specific user.
     */
    virtual int32_t GetSecInfo(int32_t userId, const sptr<IGetSecInfoCallback>& callback) = 0;

    /**
     * add user credential information, pass in credential addition method and credential information
     * (credential type, subtype, if adding user's non password credentials, pass in password authentication token),
     * and get the result / acquireinfo callback.
     *
     * param credInfo Incoming credential addition method and credential information
     * (credential type, subtype, password authentication token).
     * param callback get results / acquireinfo callback.
     */
    virtual void AddCredential(AddCredInfo& credInfo, const sptr<IIDMCallback>& callback) = 0;

    /*
     * update user credential information.
     *
     * param credInfo Incoming credential addition method and credential information
     * (credential type, subtype, password authentication token).
     * param callback update results / acquireinfo callback.
     */
    virtual void UpdateCredential(AddCredInfo& credInfo, const sptr<IIDMCallback>& callback) = 0;

    /*
     * Cancel entry and pass in challenge value.
     *
     * param challenge challenge value.
     */
    virtual int32_t Cancel(uint64_t challenge) = 0;

    /*
     * enforce delete the user credential information, pass in the callback,
     * and obtain the deletion result through the callback.
     *
     * param authToken user password authentication token.
     * param callback get deletion result through callback.
     */
    virtual int32_t EnforceDelUser(int32_t userId, const sptr<IIDMCallback>& callback) = 0;

    /*
     * delete all users credential information, pass in the user password authentication token and callback,
     * and obtain the deletion result through the callback.
     *
     * param authToken user password authentication token.
     * param callback get deletion result through callback.
     */
    virtual void DelUser(std::vector<uint8_t> authToken, const sptr<IIDMCallback>& callback) = 0;

    /*
     * delete the user credential information, pass in the credential id, password authentication token and callback,
     * and obtain the deletion result through the callback.
     * Only deleting non password credentials is supported.
     *
     * param credentialId credential index.
     * param authToken password authentication token.
     * param callback get deletion result through callback.
     */
    virtual void DelCred(uint64_t credentialId, std::vector<uint8_t> authToken,
        const sptr<IIDMCallback>& callback) = 0;

    enum {
        USERIDM_OPEN_SESSION = 0,
        USERIDM_CLOSE_SESSION,
        USERIDM_GET_AUTH_INFO,
        USERIDM_GET_AUTH_INFO_BY_ID,
        USERIDM_GET_SEC_INFO,
        USERIDM_ADD_CREDENTIAL,
        USERIDM_UPDATE_CREDENTIAL,
        USERIDM_CANCEL,
        USERIDM_ENFORCE_DELUSER,
        USERIDM_DELUSER,
        USERIDM_DELCRED,
    };
};
}  // namespace UserIDM
}  // namespace UserIAM
}  // namespace OHOS

#endif // IUSERIDM_H
