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

const hiLog = requireNapi('hilog');
const userAuth = requireNapi('userIAM.userAuth');

const DOMAIN = 0x0007;
const TAG = 'useriam_auth_icon';
const ICON_UNAVAILABLE = 0;
const ICON_AVAILABLE = 1;
const TIMEOUT_MILLISECONDS = 5000;
const INVALID_PARAMETERS = 401;
const FACE_ICON_RESOURCE = 'sys.media.ohos_user_auth_icon_face';
const FINGERPRINT_ICON_RESOURCE = 'sys.media.ohos_user_auth_icon_fingerprint';
export class UserAuthIcon extends ViewPU {
    constructor(b1, c1, d1, e1 = -1, f1 = undefined, g1) {
        super(b1, d1, e1, g1);
        if (typeof f1 === 'function') {
            this.paramsGenerator_ = f1;
        }
        this.authParam = {
            challenge: new Uint8Array(),
            authType: [],
            authTrustLevel: userAuth.AuthTrustLevel.ATL1
        };
        this.widgetParam = {
            title: ''
        };
        this.iconHeight = 64;
        this.iconColor = { 'id': -1, 'type': 10001, params: ['sys.color.ohos_id_color_activated'], 'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' };
        this.authFlag = ICON_UNAVAILABLE;
        this.__imageSource = new ObservedPropertySimplePU('', this, 'imageSource');
        this.onAuthResult = (j1) => { };
        this.onIconClick = () => { };
        this.setInitiallyProvidedValue(c1);
    }
    setInitiallyProvidedValue(a1) {
        if (a1.authParam !== undefined) {
            this.authParam = a1.authParam;
        }
        if (a1.widgetParam !== undefined) {
            this.widgetParam = a1.widgetParam;
        }
        if (a1.iconHeight !== undefined) {
            this.iconHeight = a1.iconHeight;
        }
        if (a1.iconColor !== undefined) {
            this.iconColor = a1.iconColor;
        }
        if (a1.authFlag !== undefined) {
            this.authFlag = a1.authFlag;
        }
        if (a1.imageSource !== undefined) {
            this.imageSource = a1.imageSource;
        }
        if (a1.onAuthResult !== undefined) {
            this.onAuthResult = a1.onAuthResult;
        }
        if (a1.onIconClick !== undefined) {
            this.onIconClick = a1.onIconClick;
        }
    }
    updateStateVars(z) {
    }
    purgeVariableDependenciesOnElmtId(y) {
        this.__imageSource.purgeDependencyOnElmtId(y);
    }
    aboutToBeDeleted() {
        this.__imageSource.aboutToBeDeleted();
        SubscriberManager.Get().delete(this.id__());
        this.aboutToBeDeletedInternal();
    }
    get imageSource() {
        return this.__imageSource.get();
    }
    set imageSource(x) {
        this.__imageSource.set(x);
    }
    initImageSource(v, w) {
        if (v.includes(userAuth.UserAuthType.FACE) && (!v.includes(userAuth.UserAuthType.FINGERPRINT))) {
            this.authFlag = ICON_AVAILABLE;
            this.imageSource = FACE_ICON_RESOURCE;
            return;
        }
        if ((!v.includes(userAuth.UserAuthType.FACE)) && v.includes(userAuth.UserAuthType.FINGERPRINT)) {
            this.authFlag = ICON_AVAILABLE;
            this.imageSource = FINGERPRINT_ICON_RESOURCE;
            return;
        }
        if (v.includes(userAuth.UserAuthType.FACE) && v.includes(userAuth.UserAuthType.FINGERPRINT) &&
            v.includes(userAuth.UserAuthType.PIN)) {
            this.handleAllAuthTypeCase(w);
            return;
        }
        if (v.includes(userAuth.UserAuthType.FACE) && v.includes(userAuth.UserAuthType.FINGERPRINT) &&
            !v.includes(userAuth.UserAuthType.PIN)) {
            this.authFlag = ICON_UNAVAILABLE;
            this.info('incorrect parameters.');
            this.onAuthResult({ result: INVALID_PARAMETERS });
            this.imageSource = '';
            return;
        }
        this.authFlag = ICON_UNAVAILABLE;
        this.info('incorrect parameters.');
        this.onAuthResult({ result: userAuth.UserAuthResultCode.TYPE_NOT_SUPPORT });
        this.imageSource = '';
        return;
    }
    handleAllAuthTypeCase(u) {
        if (this.checkAuthTypeSupported(userAuth.UserAuthType.FACE, u)) {
            this.info('face auth available.');
            this.authFlag = ICON_AVAILABLE;
            this.imageSource = FACE_ICON_RESOURCE;
            return;
        }
        if (this.checkAuthTypeSupported(userAuth.UserAuthType.FINGERPRINT, u)) {
            this.info('finger auth available.');
            this.authFlag = ICON_AVAILABLE;
            this.imageSource = FINGERPRINT_ICON_RESOURCE;
            return;
        }
        this.authFlag = ICON_AVAILABLE;
        this.imageSource = FACE_ICON_RESOURCE;
        return;
    }
    checkAuthTypeSupported(r, s) {
        this.info(`check if it is supported, authType: ${r} authTrustLevel: ${s}.`);
        try {
            userAuth.getAvailableStatus(r, s);
            this.info('current auth trust level is supported.');
            return true;
        }
        catch (t) {
            this.error(`current auth trust level is not supported, error = ${t}.`);
            return false;
        }
    }
    info(q) {
        if (hiLog.isLoggable(DOMAIN, TAG, hiLog.LogLevel.INFO)) {
            hiLog.info(DOMAIN, TAG, q);
        }
    }
    error(p) {
        if (hiLog.isLoggable(DOMAIN, TAG, hiLog.LogLevel.ERROR)) {
            hiLog.error(DOMAIN, TAG, p);
        }
    }
    aboutToAppear() {
        this.info('before init image source.');
        if (this.authParam.authType === undefined || this.authParam.authTrustLevel === undefined) {
            this.authFlag = ICON_UNAVAILABLE;
            this.info('incorrect parameters.');
            this.onAuthResult({ result: INVALID_PARAMETERS });
            this.imageSource = '';
            return;
        }
        this.initImageSource(this.authParam.authType, this.authParam.authTrustLevel);
        this.info(`after init image source, imageSource = ${this.imageSource}.`);
    }
    initialRender() {
        this.observeComponentCreation2((n, o) => {
            Row.create();
        }, Row);
        this.observeComponentCreation2((l, m) => {
            Column.create();
        }, Column);
        this.observeComponentCreation2((d, e) => {
            Image.create({ 'id': this.imageSource, params: [], 'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' });
            Image.width(this.iconHeight);
            Image.height(this.iconHeight);
            Image.fillColor(this.iconColor);
            Image.onClick(() => {
                this.info('start handle click event.');
                if (this.onIconClick !== undefined) {
                    this.info('click event has response.');
                    this.onIconClick();
                }
                if (this.authFlag === ICON_AVAILABLE) {
                    try {
                        let h = userAuth.getUserAuthInstance(this.authParam, this.widgetParam);
                        let i = setTimeout(() => {
                            this.error('auth timeout.');
                            h.cancel();
                            this.onAuthResult({ result: userAuth.UserAuthResultCode.GENERAL_ERROR });
                        }, TIMEOUT_MILLISECONDS);
                        this.info('get userAuth instance success.');
                        h.on('result', {
                            onResult: (k) => {
                                this.info(`userAuthInstance callback result = ${JSON.stringify(k)}.`);
                                this.onAuthResult(k);
                                h.off('result');
                            }
                        });
                        this.info('auth before start.');
                        h.start();
                        this.info('auth start success.');
                        clearTimeout(i);
                    }
                    catch (g) {
                        if (g) {
                            this.error(`auth catch error, code: ${g.code}, message: ${g.message}`);
                            this.onAuthResult({ result: g.code });
                            return;
                        }
                        this.error('auth error.');
                        this.onAuthResult({ result: userAuth.UserAuthResultCode.GENERAL_ERROR });
                    }
                }
                this.info('end handle click event.');
            });
        }, Image);
        Column.pop();
        Row.pop();
    }
    rerender() {
        this.updateDirtyElements();
    }
}
