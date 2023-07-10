/**
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

import userAuth from '@ohos.userIAM.userAuth';
import LogUtils from '../../common/utils/LogUtils';
import Constants from '../../common/vm/Constants';
import AuthUtils from '../utils/AuthUtils';
import TimeUtils from '../utils/TimeUtils';

const TAG = 'SixPwd';
const INTERVAL = 1000;

@Component
export default struct SixPwd {
  @Link textValue: string;
  @Link inputValue: string;
  @Link isEdit: boolean;

  countTime(freezingTime): void {
    const TRY_AGAIN = globalThis.context.resourceManager.getStringSync($r('app.string.unified_authwidget_postretry'));
    let promptText: string = '';
    let freezingMillisecond = freezingTime;
    if (freezingMillisecond > 0) {
      promptText = TimeUtils.getFreezingTimeNm(freezingMillisecond, globalThis.context);
      promptText = globalThis.context.resourceManager
        .getStringSync($r('app.string.unified_authwidget_many_failures')) + promptText + TRY_AGAIN;
      setTimeout(this.countTime.bind(this), INTERVAL, freezingTime - INTERVAL);
    } else {
      promptText = ' ';
      this.isEdit = true;
    }
    this.inputValue = promptText;
  }

  build() {
    Column() {
      Text(globalThis.wantParams?.title)
        .margin({ top: $r('app.float.content_padding_top') })
        .fontSize($r('sys.float.ohos_id_text_size_body1'))
        .fontColor($r('sys.color.ohos_id_color_text_primary'))
        .fontWeight(FontWeight.Medium)
      Column() {
        Stack() {
          TextInput({ placeholder: '', text: this.textValue })
            .onChange(async (value: string) => {
              this.textValue = value
              if (value.length === 6) {
                // check callback
                let userAuthWidgetMgr;
                try {
                  let that = this;
                  LogUtils.i(TAG, 'getUserAuthWidgetMgr start');
                  userAuthWidgetMgr = await userAuth.getUserAuthWidgetMgr(Constants.userAuthWidgetMgrVersion);
                  userAuthWidgetMgr.on('command', {
                    callback: function (result) {
                      LogUtils.i(TAG, 'userAuthWidgetMgr onCommand result: ' + JSON.stringify(result));
                      const cmdData = JSON.parse(result?.cmdData)
                      if (cmdData?.cmd?.[0]?.payload?.result === Constants.userAuthWidgetMgrSuccess) {
                        // success
                        globalThis.session?.terminateSelf?.();
                      } else {
                        // fail
                        // frequency
                        const frequency = cmdData?.cmd?.[0]?.payload?.remainAttempts;
                        if (frequency) {
                          that.inputValue = globalThis.context.resourceManager
                            .getStringSync($r('app.string.unified_authwidget_hint_pwd_error'));
                          that.textValue = '';
                          if (frequency < 3) {
                            that.inputValue = globalThis.context.resourceManager
                              .getStringSync($r('app.string.unified_authwidget_pwd_error_can_try'))
                            + frequency + globalThis.context.resourceManager
                              .getStringSync($r('app.string.unified_authwidget_frequency'));
                          }
                          return;
                        }
                        // countdown
                        const time = cmdData?.cmd?.[0]?.payload?.lockoutDuration;
                        if (frequency === 0 && time) {
                          that.countTime(time);
                          that.isEdit = false;
                          that.textValue = '';
                          return;
                        }
                        that.inputValue = globalThis.context.resourceManager
                          .getStringSync($r('app.string.unified_authwidget_hint_pwd_error'));
                        that.textValue = '';
                      }
                    }
                  });
                  LogUtils.i(TAG, 'getUserAuthWidgetMgr success');
                } catch (error) {
                  LogUtils.e(TAG, 'getUserAuthWidgetMgr catch error: ' + JSON.stringify(error));
                }

                // check
                AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypePin]);
              }
            })
            .backgroundImageSize(ImageSize.Auto)
            .enabled(this.isEdit)
            .maxLength(6)
            .visibility(Visibility.Visible)
            .opacity(0)
            .caretColor('transparent')
            .id('pinSix')
          List({ space: 4 }) {
            ForEach(['', '', '', '', '', ''], (item, index) => {
              ListItem() {
                Button()
                  .border({
                    color: Color.Black,
                    style: BorderStyle.Solid,
                    width: this.textValue.length !== 0 && index < this.textValue.length ? '6vp' : 1
                  })
                  .type(ButtonType.Circle)
                  .backgroundColor(Color.White)
                  .width($r('app.float.input_btn_size'))
                  .height($r('app.float.input_btn_size'))
                  .borderRadius($r('app.float.input_btn_size'))
                  .margin(index > 0 ? { left: $r('app.float.input_btn_padding_around') } : {})
                  .focusable(true)
              }
            }, item => item)
          }
          .listDirection(Axis.Horizontal)
          .height($r('app.float.input_btn_size'))
        }
      }
      .margin({ top: $r('app.float.content_padding') })
      .padding({ top: $r('app.float.input_btn_padding_up_down'), bottom: $r('app.float.input_btn_padding_up_down') })

      Text(this.inputValue)
        .fontSize($r('sys.float.ohos_id_text_size_body2'))
        .margin({ top: $r('app.float.element_margin') })
        .fontColor($r('sys.color.ohos_id_color_warning'))
    }
  }
}