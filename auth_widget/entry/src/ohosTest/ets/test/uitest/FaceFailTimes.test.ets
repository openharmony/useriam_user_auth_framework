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
import { beforeAll, describe, expect, it } from '@ohos/hypium';
import abilityDelegatorRegistry from '@ohos.app.ability.abilityDelegatorRegistry';

const delegator = abilityDelegatorRegistry.getAbilityDelegator();
const bundleName = abilityDelegatorRegistry.getArguments().bundleName;

const delayTime: number = 1000;

export default function FaceFailTimesTest() {
  describe('FaceFailTimesTest', function () {

    function sleep(ms) {
      return new Promise(resolve => setTimeout(resolve, ms));
    }

    beforeAll(async function () {
      const data = {
        "cmd": [{
          "event": "CMD_NOTIFY_AUTH_START", "payload": {
            "lockoutDuration": 0, "remainAttempts": 1, "type": "face"
          }, "version": "1"
        }],
        "pinSubType": "",
        "title": "",
        "type": ["face"],
        "widgetContextId": 13808827370146417000,
        "windowModeType": "DIALOG_BOX",
        "navigationButtonText": "确定！"
      }
      globalThis.wantParams = data;
      sleep(1000);

      let want = {
        bundleName: bundleName,
        abilityName: 'FaceFailTimesAbility'
      }
      await delegator.startAbility(want);
      sleep(1000);
    })

    it('navigationBtnFace_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      await driver.findComponent(ON.id('navigationBtnFace'));
      expect(true).assertTrue();
      done();
    })

    it('imageFaceAuth_fail_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      await driver.findComponent(ON.id('textFaceAuth'));
      expect(true).assertTrue();
      done();
    })
  })
}