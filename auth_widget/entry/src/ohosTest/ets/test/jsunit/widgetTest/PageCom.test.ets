/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License")
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

import { Driver, ON } from '@ohos.UiTest';
import userAuth from '@ohos.userIAM.userAuth';
import { beforeAll, describe, expect, it } from '@ohos/hypium';
import LogUtils from '../../../../../main/ets/common/utils/LogUtils';

const TAG = 'PageComTest';

const delayTime: number = 1000;

export default function PageComTest() {
  describe('pageComTest', function () {

    function sleep(time) {
      return new Promise((resolve) => setTimeout(resolve, time));
    }

    beforeAll(async function () {
      let userAuthInstance = null;
      const authParam = {
        challenge: new Uint8Array([49, 49, 49, 49, 49, 49]),
        authType: [userAuth.UserAuthType.FINGERPRINT],
        authTrustLevel: 10000,
      };
      const widgetParam = {
        title: '',
        windowMode: 1,
        navigationButtonText: '',
      };
      userAuthInstance = await userAuth.getUserAuthInstance(authParam, widgetParam);
      userAuthInstance.on('result', {
        callback: function (result) {
          LogUtils.i(TAG, 'userAuthInstance onResult: ' + JSON.stringify(result));
        }
      });
      userAuthInstance.start();
    })

    it('clickEventOk_Input', 0, async function (done) {
      let userAuthInstance = null;
      const authParam = {
        challenge: new Uint8Array([49, 49, 49, 49, 49, 49]),
        authType: [userAuth.UserAuthType.FINGERPRINT],
        authTrustLevel: 10000,
      };
      const widgetParam = {
        title: '',
        windowMode: 1,
        navigationButtonText: '',
      };
      userAuthInstance = await userAuth.getUserAuthInstance(authParam, widgetParam);
      userAuthInstance.on('result', {
        callback: function (result) {
          LogUtils.i(TAG, 'userAuthInstance onResult: ' + JSON.stringify(result));
        }
      });
      let driver = Driver.create();
      await driver.delayMs(delayTime);

      let btn = await driver.findComponent(ON.id('cancelBtn_dialog_pwd'));
      LogUtils.i(TAG, 'btn: ' + JSON.stringify(btn));
      await btn.click();
      expect(true).assertTrue();
      done();
    })
  })
}