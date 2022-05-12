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

import{AsyncCallback} from './basic';

/**
 * User authentication
 * @since 8
 * @sysCap SystemCapability.UserIAM.UserAuth.BiometricAuth
 * @devices phone, tablet
 * @permission ohos.permission.ACCESS_USER_AUTH_INTERNAL
 */
declare namespace userIAM
{
    class UserAuth
    {
        /**
         * Constructor used to get a UserAuth instance.
         * @since 8
         * @SysCap SystemCapability.UserIAM.UserAuth.BiometricAuth
         * @return Returns a UserAuth instance.
         */
        constructor();

        /**
         * Gets version information.
         * @since 8
         * @SysCap SystemCapability.UserIAM.UserAuth.BiometricAuth
         * @return Returns version information.
         */
        getVersion() : number;

        /**
         * Checks whether the authentication capability is available.
         * @since 8
         * @SysCap SystemCapability.UserIAM.UserAuth.BiometricAuth
         * <p>Permissions required: {@code ohos.permission.ACCESS_USER_AUTH_INTERNAL}
         * @param authType Credential type for authentication.
         * @param authTrustLevel Credibility level of the authentication result.
         * @return Returns the check result, which is specified by getAvailableStatus.
         */
        getAvailableStatus(authType : AuthType, authTrustLevel : AuthTrustLevel) : number;

        /**
         * Gets properties by passing in the credential type and key.
         * @since 8
         * @SysCap SystemCapability.UserIAM.UserAuth.BiometricAuth
         * <p>Permissions required: {@code ohos.permission.ACCESS_USER_AUTH_INTERNAL}
         * @param request Credential type and the key value.
         * @return Returns properties corresponding to the specified key.
         */
        getProperty(request : GetPropertyRequest) : Promise<ExecutorProperty>;
        getProperty(request: GetPropertyRequest, callback: AsyncCallback<ExecutorProperty>): void

        /**
         * Sets properties that can be used to initialize algorithms.
         * @since 8
         * @SysCap SystemCapability.UserIAM.UserAuth.BiometricAuth
         * <p>Permissions required: {@code ohos.permission.ACCESS_USER_AUTH_INTERNAL}
         * @param request Credential type and the key value.
         * @return Returns a number indicating whether the property setting was successful.
         */
        setProperty(request: SetPropertyRequest): Promise<number>;
        setProperty(request: SetPropertyRequest, callback: AsyncCallback<number>): void

        /**
         * Performs authentication based on the specified challenge value, authentication type, trust level and callback.
         * @since 8
         * @SysCap SystemCapability.UserIAM.UserAuth.BiometricAuth
         * <p>Permissions required: {@code ohos.permission.ACCESS_USER_AUTH_INTERNAL}
         * @param challenge Challenge value.
         * @param authType Authentication type.
         * @param authTrustLevel Credibility level of certification results.
         * @param callback Callback used to return results and acquireinfo.
         * @return Returns the authentication result and acquireinfo through callback.
         */
        auth(challenge: Uint8Array, authType: AuthType, authTrustLevel: AuthTrustLevel, callback: IUserAuthCallback): Uint8Array;

        /**
         * Performs user authentication based on the specified user ID, challenge value, authentication type, trust level and callback.
         * @since 8
         * @SysCap SystemCapability.UserIAM.UserAuth.BiometricAuth
         * <p>Permissions required: {@code ohos.permission.ACCESS_USER_AUTH_INTERNAL}
         * @param userId User ID.
         * @param challenge Challenge value.
         * @param authType Authentication type.
         * @param authTrustLevel Credibility level of the authentication result.
         * @param callback Callback used to return the result and acquireinfo.
         * @return Returns the result and acquireinfo through the callback.
         */
        authUser(userId: number, challenge: Uint8Array, authType: AuthType, authTrustLevel: AuthTrustLevel, callback : IUserAuthCallback): Uint8Array;

        /**
         * Cancels authentication based on the specified ContextID.
         * @since 8
         * @SysCap SystemCapability.UserIAM.UserAuth.BiometricAuth
         * <p>Permissions required: {@code ohos.permission.ACCESS_USER_AUTH_INTERNAL}
         * @param contextID Context ID.
         * @return Returns a number indicating whether authentication was cancelled successfully.
         */
        cancelAuth(contextID : Uint8Array) : number;
    }

    /**
     * Credential type for authentication
     */
    enum AuthType {
        /**
         * Authentication type: pin.
         * @since 8
         */
        PIN = 1,
        /**
         * Authentication type: face.
         * @since 8
         */
        FACE = 2
    }

    /**
     * Credential subtype: 6-digit digital password, user-defined digital password,
     * user-defined mixed password, 2D face, 3D face
     */
    enum AuthSubType{
        /**
         * Authentication sub type: 6-digit pin.
         * @since 8
         */
        PIN_SIX = 10000,
        /**
         * Authentication sub type: self defined number pin.
         * @since 8
         */
        PIN_NUMBER = 10001,
        /**
         * Authentication sub type: mixed pin.
         * @since 8
         */
        PIN_MIXED = 10002,
        /**
         * Authentication sub type: 2D face.
         * @since 8
         */
        FACE_2D = 20000,
        /**
         * Authentication sub type 3D face.
         * @since 8
         */
        FACE_3D = 20001
    }

    /**
     * Credibility level of authentication results
     */
    enum AuthTrustLevel {
        /**
         * Authentication result trust level 1
         * @since 8
         */
        ATL1 = 10000,
        /**
         * Authentication result trust level 2
         * @since 8
         */
        ATL2 = 20000,
        /**
         * Authentication result trust level 3
         * @since 8
         */
        ATL3 = 30000,
        /**
         * Authentication result trust level 4
         * @since 8
         */
        ATL4 = 40000
    }

    /**
     * Authentication properties
     */
    enum GetPropertyType {
        /**
         * Authentication sub type
         * @since 8
         */
        AUTH_SUB_TYPE = 1,
        /**
         * Remaining authentication times
         * @since 8
         */
        REMAIN_TIMES = 2,
        /**
         * Authentication freezing time
         * @since 8
         */
        FREEZING_TIME = 3
    }

    /**
     * Gets authentication properties based on the specified authenticaiton type and key.
     * requested to be obtained
     * @since 8
     */
    interface GetPropertyRequest {
        authType : AuthType;
        keys : Array<GetPropertyType>;
    }

    /**
     * Executor properties: subtype, remaining authentication times, and authentication freezing time.
     * @since 8
     */
    interface ExecutorProperty {
        result: number;
        authSubType : AuthSubType;
        remainTimes ?: number;
        freezingTime ?: number;
    }

    /**
     * Authentication property list
     * @since 8
     */
    enum SetPropertyType {
        /**
         * init algorithm
         * @since 8
         */
        INIT_ALGORITHM = 1,
    }

    /**
     * Sets authentication properties based on the specified authenticaiton type and key.
     * @since 8
     */
    interface SetPropertyRequest {
        authType : AuthType;
        key : SetPropertyType;
        setInfo : Uint8Array;
    }

    /**
     * Executor properties: subclass, remaining authentication times, and authentication freezing time.
     * @since 8
     */
    interface ExecutorProperty {
        result : number;
        authSubType : AuthSubType;
        remainTimes ?: number;
        freezingTime ?: number;
    }

    /**
     * Authentication method and priority: currently only face supported
     * @since 8
     */
    enum AuthMethod {
        /**
         * Authentication method: PIN
         * @since 8
         */
        PIN_ONLY = 0xF,
        /**
         * Authentication method: face
         * @since 8
         */
        FACE_ONLY = 0xF0
    }

    /**
     * Callback used to return the authentication result. If the authentication is passed, the authentication
     * token is returned in extrainfo. If the authentication fails, the number of remaining authentication times is returned in extrainfo.
     * If the authentication executor is locked, the authentication freezing time or acquireinfo is returned in extrainfo.
     * @since 8
     */
    interface IUserAuthCallback {
        onResult: (result : number, extraInfo : AuthResult) => void;
        onAcquireInfo ?: (module : number, acquire : number, extraInfo : any) => void
    }

    /**
     * Module returning acquireinfo.
     * @since 8
     */
    enum Module {
        /**
         * FaceAuth
         * @since 8
         */
        FACE_AUTH = 1
    }

    /**
     * Authentication result: authentication token, remaining authentication times, and authentication freezing time
     * @since 8
     */
    interface AuthResult {
        token ?: Uint8Array;
        remainTimes ?: number;
        freezingTime ?: number;
    }

    /**
     * Result code
     * @since 8
     */
    enum ResultCode {
        /**
         * Indicates that authentication is successful or ability is supported.
         * @since 8
         */
        SUCCESS = 0,
        /**
         * Indicates that the authentication fails to identify user.
         * @since 8
         */
        FAIL = 1,
        /**
         * Indicates other errors.
         */
        GENERAL_ERROR = 2,
        /**
         * Indicates that authentication has been canceled.
         * @since 8
         */
        CANCELED = 3,
        /**
         * Indicates that authentication has timed out.
         * @since 8
         */
        TIMEOUT = 4,
        /**
         * Indicates that the authentication type is not supported.
         * @since 8
         */
        TYPE_NOT_SUPPORT = 5,
        /**
         * Indicates that the authentication trust level is not supported.
         * @since 8
         */
        TRUST_LEVEL_NOT_SUPPORT = 6,
        /**
         * Indicates that the authentication task is busy. Wait for a few seconds and try again.
         * @since 8
         */
        BUSY = 7,
        /**
         * Indicates incorrect parameters.
         * @since 8
         */
        INVALID_PARAMETERS = 8,
        /**
         * Indicates that the authenticator is locked.
         * @since 8
         */
        LOCKED = 9,
        /**
         * Indicates that the user has not enrolled the authenticator.
         * @since 8
         */
        NOT_ENROLLED = 10
    }

    /**
     * Enumeration of prompt codes during authentication.
     * @since 8
     */
    enum FaceTipsCode {
        /**
         * Indicates that the obtained facial image is too bright due to high illumination.
         * @since 8
         */
        FACE_AUTH_TIP_TOO_BRIGHT = 1,
        /**
         * Indicates that the obtained facial image is too dark due to low illumination.
         * @since 8
         */
        FACE_AUTH_TIP_TOO_DARK = 2,
        /**
         * Indicates that the face is too close to the device.
         * @since 8
         */
        FACE_AUTH_TIP_TOO_CLOSE = 3,
        /**
         * Indicates that the face is too far away from the device.
         * @since 8
         */
        FACE_AUTH_TIP_TOO_FAR = 4,
        /**
         * Indicates that the device is too high, and that only the upper part of the face is captured.
         * @since 8
         */
        FACE_AUTH_TIP_TOO_HIGH = 5,
        /**
         * Indicates that the device is too low, and that only the lower part of the face is captured.
         * @since 8
         */
        FACE_AUTH_TIP_TOO_LOW = 6,
        /**
         * Indicates that the device is deviated to the right, and that only the right part of the face is captured.
         * @since 8
         */
        FACE_AUTH_TIP_TOO_RIGHT = 7,
        /**
         * Indicates that the device is deviated to the left, and that only the left part of the face is captured.
         * @since 8
         */
        FACE_AUTH_TIP_TOO_LEFT = 8,
        /**
         * Indicates that the face moves too fast during facial information collection.
         * @since 8
         */
        FACE_AUTH_TIP_TOO_MUCH_MOTION = 9,
        /**
         * Indicates that the face is not facing the device.
         * @since 8
         */
        FACE_AUTH_TIP_POOR_GAZE = 10,
        /**
         * Indicates that no face is detected.
         * @since 8
         */
        FACE_AUTH_TIP_NOT_DETECTED = 11,
    }

    /**
     * Indicates the enumeration of prompt codes in the process of fingerprint authentication
     * @since 8
     */
    enum FingerprintTips {
        /**
         * Indicates that the image acquired is good.
         * @since 8
         */
        FINGERPRINT_TIP_GOOD = 0,
        /**
         * Indicates that the fingerprint image is too noisy due to suspected or detected dirt on the sensor.
         * @since 8
         */
        FINGERPRINT_TIP_IMAGER_DIRTY = 1,
        /**
         * Indicates that the fingerprint image is too noisy to process due to a detected condition.
         * @since 8
         */
        FINGERPRINT_TIP_INSUFFICIENT = 2,
        /**
         * Indicates that only a partial fingerprint image is detected.
         * @since 8
         */
        FINGERPRINT_TIP_PARTIAL = 3,
        /**
         * Indicates that the fingerprint image is incomplete due to quick motion.
         * @since 8
         */
        FINGERPRINT_TIP_TOO_FAST = 4,
        /**
         * Indicates that the fingerprint image is unreadable due to lack of motion.
         * @since 8
         */
        FINGERPRINT_TIP_TOO_SLOW = 5
    }
}
export default userIAM;
