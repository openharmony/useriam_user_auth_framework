/*
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

import deviceInfo from '@ohos.deviceInfo';
import Constants from '../vm/Constants';

const DIGITAL_BUTTON_DIAMETER = 60;
const DIGITAL_BUTTON_RECT_WH = 100;
const DIGITAL_BUTTON_RECT_HH = 50;
const DEL_PASSWORD = -2;
const CALL_PHONE = -1;
const GO_BACK = -3;

@Component
export default struct NumKeyBoard {
  private onKeyPress: (params, callback) => void;
  @StorageLink('numKeyboard') numKeyboard: any[] = Constants.numKeyBoard;

  build() {
    Flex({ direction: FlexDirection.Column, alignItems: ItemAlign.Center, justifyContent: FlexAlign.Center }) {
      Grid() {
        ForEach(this.numKeyboard, (item: any) => {
          GridItem() {
            Stack({ alignContent: Alignment.Center }) {
              Column({ space: 0 }) {
                Flex({
                  direction: FlexDirection.Column,
                  alignItems: ItemAlign.Center,
                  justifyContent: FlexAlign.Center
                }) {
                  if (item.value === CALL_PHONE || item.value === GO_BACK || item.value === DEL_PASSWORD) {
                    Text(item.row1)
                      .id('textNumKeyBordCustomPwd' + item.index)
                      .fontSize($r('app.float.digital_password_prompt_font_size'))
                      .fontWeight(FontWeight.Medium)
                      .fontColor(Color.White)
                      .textAlign(TextAlign.Center)
                      .width(Constants.fullContainerWidth)
                      .padding($r('app.float.numkeyBoard_rowsGap'))
                      .margin($r('app.float.numkeyBoard_rowsGap'))
                  } else {
                    Text(item.row1)
                      .id('textNumKeyBordCustomPwd' + item.index)
                      .fontSize($r('app.float.digital_password_row1_font_size'))
                      .fontWeight(FontWeight.Medium)
                      .fontColor(Color.White)
                      .textAlign(TextAlign.Center)
                      .width(Constants.fullContainerWidth)
                      .padding($r('app.float.numkeyBoard_rowsGap'))
                      .margin($r('app.float.numkeyBoard_rowsGap'))
                  }
                  if (!!item.row2) {
                    Text(item.row2)
                      .fontSize($r('app.float.digital_password_row2_font_size'))
                      .fontWeight(FontWeight.Regular)
                      .fontColor(Color.White)
                      .opacity($r('app.float.numkeyBoard_text_opacity'))
                      .textAlign(TextAlign.Center)
                      .width(Constants.fullContainerWidth)
                      .padding($r('app.float.numkeyBoard_rowsGap'))
                      .margin($r('app.float.numkeyBoard_rowsGap'))
                  }
                }
                .width(Constants.fullContainerWidth)
                .height($r('app.float.keyboard_key_high'))
              }

              if (deviceInfo.deviceType === 'tablet') {
                if (item.value === CALL_PHONE || item.value === GO_BACK || item.value === DEL_PASSWORD) {
                  Column() {
                    Button({ type: ButtonType.Normal, stateEffect: true })
                      .backgroundColor($r('app.color.button_color'))
                      .width(DIGITAL_BUTTON_RECT_WH)
                      .height(DIGITAL_BUTTON_RECT_HH)
                  }
                } else {
                  Column() {
                    Button({ type: ButtonType.Circle })
                      .backgroundColor($r('app.color.button_color'))
                      .width(DIGITAL_BUTTON_DIAMETER)
                      .height(DIGITAL_BUTTON_DIAMETER)
                  }
                }
              }
            }
            .onClick(() => {
              setTimeout(this.onKeyPress.bind(this), 0, item.index, () => {
              });
            })
            .id('numKeyBordCustomPwd' + item.index)
          }
        })
      }
      .columnsTemplate('1fr 1fr 1fr')
      .rowsTemplate('1fr 1fr 1fr 1fr')
      .rowsGap($r('app.float.numkeyBoard_rowsGap'))
      .width(Constants.fullContainerWidth)
      .height(Constants.fullContainerHeight)
    }
    .width(Constants.fullContainerWidth)
    .height(Constants.fullContainerHeight)
  }
}