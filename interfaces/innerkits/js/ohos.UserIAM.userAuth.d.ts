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

import{AsyncCallback} from './basic';

declare namespace userIAM
{
    class UserAuth 
    {
        /**
         * constructor.
         *
         * @return Constructor to get the userauth class instance
         */
        constructor();

        /**
         * getVersion.
         *
         * @return Get version information
         */
        getVersion() : number;

        /**
         * getAvailabeStatus.
         *
         * <p>Permissions required: {@code ohos.permission.ACCESS_USER_AUTH}
         *
         * @param authType Credential type for authentication.
         * @param authTrustLevel Credibility level of certification results.
         * @return number.
         */
        getAvailabeStatus(authType : AuthType, authTrustLevel : AuthTurstLevel) : number;
        /**
         * getProperty.
         *
         * <p>Permissions required: {@code ohos.permission.ACCESS_USER_AUTH}
         *
         * @param request the attribute field list, authentication credential type, and credential subclass.
         * @return ExecutorProperty: Get the attribute, pass in the credential type and the key to get, and return the value
         * corresponding to the key (support to query subclasses / remaining authentication times / freezing time)
         */
        getProperty(request : GetPropertyRequest) : Promise<ExecutorProperty>;
        getProperty(request: GetPropertyRequest, callback: AsyncCallback<ExecutorProperty>): void

        /**
         * getProperty.
         *
         * <p>Permissions required: {@code ohos.permission.ACCESS_USER_AUTH}
         *
         * @param request pass in the credential type and the key value to be set.
         * @return number.
         */
        setProperty(request: SetPropertyRequest): Promise<number>;
        setProperty(request: SetPropertyRequest, callback: AsyncCallback<number>): void

        /**
         * auth
         *
         * <p>Permissions required: {@code ohos.permission.ACCESS_USER_AUTH}
         *
         * @param challenge pass in challenge value.
         * @param authMethod authentication method.
         * @param authTrustLevel Credibility level of certification results.
         * @param callback Return results and acquireinfo through callback.
         * @return BigInt.
         */
        auth(challenge: BigInt, authMethod: number, authTrustLevel: AuthTurstLevel, callback: IUserAuthCallback): BigInt;

        /**
         * authUser
         *
         * <p>Permissions required: {@code ohos.permission.ACCESS_USER_AUTH}
         *
         * @param userId Incoming user ID.
         * @param challenge pass in challenge value.
         * @param authMethod authentication method.
         * @param authTrustLevel Credibility level of certification results.
         * @param callback Return results and acquireinfo through callback.
         * @return BigInt.
         */
        authUser(userId: number, challenge: BigInt, authMethod: number, authTrustLevel: AuthTurstLevel, callback : IUserAuthCallback): BigInt;

        /**
         * getProperty.
         *
         * <p>Permissions required: {@code ohos.permission.ACCESS_USER_AUTH}
         *
         * @param contextID Cancel authentication and pass in ContextID.
         * @return number.
         */
        cancelAuth(contextID : BigInt) : number;
    }
    
    /**
     * Credential type for authentication
     */
    enum AuthType {
        /**
         * Authentication type pin.
         */
        PIN = 1,
        /**
         * Authentication type face.
         */
        FACE = 2
    }
    
    /**
     * Credential subtype: 6-digit digital password, user-defined digital password, 
     * user-defined mixed password, 2D face, 3D face
     */
    enum AuthSubType{
        /**
         * Authentication sub type six number pin.
         */
        PIN_SIX = 10000,
        /**
         * Authentication sub type self defined number pin.
         */
        PIN_NUMBER = 10001,
        /**
         * Authentication sub type 2D face.
         */
        PIN_MIXED = 10002,
        /**
         * Authentication sub type 2D face.
         */
        FACE_2D = 20000,
        /**
         * Authentication sub type 3D face.
         */
        FACE_3D = 20001
    }

    /**
     * Credibility level of certification results
     */
    enum AuthTurstLevel {
        /**
         * Authentication result trusted level 1.
         */
        ATL1 = 10000,
        /**
         * Authentication result trusted level 2.
         */
        ATL2 = 20000,
        /**
         * Authentication result trusted level 3.
         */
        ATL3 = 30000,
        /**
         * Authentication result trusted level 4.
         */
        ATL4 = 40000
    }

    /**
     * Actuator attribute list
     */
    enum GetPropertyType {
        /**
         * Authentication remain times.
         */
        AUTH_SUB_TYPE = 1,
        /**
         * Authentication remain times.
         */
        REMAIN_TIMES = 2,
        /**
         * Authentication freezing time.
         */
        FREEZING_TIME = 3
    }

    /**
     * Get attribute request: the attribute field list, authentication credential type, and credential subclass
     * requested to be obtained
     */
    interface GetPropertyRequest {
        authType : AuthType;
        keys : Array<GetPropertyType>;
    }

    /**
     * Actuator attribute: subclass, remaining authentication times, freezing time
     */
    interface ExecutorProperty {
        result: number;
        authSubType : AuthSubType;
        remainTimes ?: number;
        freezingTime ?: number;
    }

    /**
     * Actuator attribute list
     */
    enum SetPropertyType {
        /**
         * init algorithm.
         */
        INIT_ALGORITHM = 1,
    }

    /**
     * Set attribute request: pass in the credential type and the key value to be set
     */
    interface SetPropertyRequest {
        authType : AuthType;
        key : SetPropertyType;
        setInfo : Uint8Array;
    }
    /**
     * Actuator attribute: subclass, remaining authentication times, freezing time
     */
    interface ExecutorProperty {
        result : number;
        authSubType : AuthSubType;
        remainTimes ?: number;
        freezingTime ?: number;
    }
    /**
     * Authentication method and priority: currently only faces are supported
     */
    enum AuthMethod {
        /**
         * Authentication method PIN.
         */
        PIN_ONLY = 0xF,
        /**
         * Authentication method face.
         */
        FACE_ONLY = 0xF0
    }

    /**
     * The authentication result code is returned through the callback, the authentication is passed, the authentication
     * token is returned in extrainfo, the authentication fails, the remaining authentication times are returned in
     * extrainfo, the authentication actuator is locked, and the freezing time / acquireinfo is returned in extrainfo
     */
    interface IUserAuthCallback {
        onResult: (result : number, extraInfo : AuthResult) => void;
        onAcquireInfo ?: (module : number, acquire : number, extraInfo : any) => void
    }

    /**
     * Returns the module of acquireinfo
     */
    enum Module {
        /**
         * Acquire information from FaceAuth.
         */
        FACE_AUTH = 1
    }

    /**
     * Authentication result: authentication token, remaining authentication times, freezing time
     */
    interface AuthResult {
        token ?: Uint8Array;
        remainTimes ?: number;
        freezingTime ?: number;
    }

    /**
     * Result code
     */
    enum ResultCode {
        /**
         * Indicates that authentication is success or ability is supported.
         */
        SUCCESS = 0,
        /**
         * Indicates the authenticator fails to identify user.
         */
        FAIL = 1,
        /**
         * Indicates other errors.
         */
        GENERAL_ERROR = 2,
        /**
         * Indicates that authentication has been canceled.
         */
        CANCELED = 3,
        /**
         * Indicates that authentication has timed out.
         */
        TIMEOUT = 4,
        /**
         * Indicates that this authentication type is not supported.
         */
        TYPE_NOT_SUPPORT = 5,
        /**
         * Indicates that the authentication trust level is not supported.
         */
        TRUST_LEVEL_NOT_SUPPORT = 6,
        /**
         * Indicates that the authentication task is busy. Wait for a few seconds and try again.
         */
        BUSY = 7,
        /**
         * Indicates incorrect parameters.
         */
        INVALID_PARAMETERS = 8,
        /**
         * Indicates that the authenticator is locked.
         */
        LOCKED = 9,
        /**
         * Indicates that the user has not enrolled the authenticator.
         */
        NOT_ENROLLED = 10
    }

    /**
     * Enumeration of prompt codes during authentication
     */
    enum FaceTipsCode {
        /**
         * Indicates that the obtained facial image is too bright due to high illumination.
         */
        FACE_AUTH_TIP_TOO_BRIGHT = 1,
        /**
         * Indicates that the obtained facial image is too dark due to low illumination.
         */
        FACE_AUTH_TIP_TOO_DARK = 2,
        /**
         * Indicates that the face is too close to the device.
         */
        FACE_AUTH_TIP_TOO_CLOSE = 3,
        /**
         * Indicates that the face is too far away from the device.
         */
        FACE_AUTH_TIP_TOO_FAR = 4,
        /**
         * Indicates that the device is too high, and that only the upper part of the face is captured.
         */
        FACE_AUTH_TIP_TOO_HIGH = 5,
        /**
         * Indicates that the device is too low, and that only the lower part of the face is captured.
         */
        FACE_AUTH_TIP_TOO_LOW = 6,
        /**
         * Indicates that the device is deviated to the right, and that only the right part of the face is captured.
         */
        FACE_AUTH_TIP_TOO_RIGHT = 7,
        /**
         * Indicates that the device is deviated to the left, and that only the left part of the face is captured.
         */
        FACE_AUTH_TIP_TOO_LEFT = 8,
        /**
         * Indicates that the face moves too fast during facial information collection.
         */
        FACE_AUTH_TIP_TOO_MUCH_MOTION = 9,
        /**
         * Indicates that the face is not facing the device.
         */
        FACE_AUTH_TIP_POOR_GAZE = 10,
        /**
         * Indicates that no face is detected.
         */
        FACE_AUTH_TIP_NOT_DETECTED = 11,
    }

}

export default userIAM;