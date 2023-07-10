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

const DIGITALPSD_BUTTON_DIAMETER = 60;
const DIGITALPSD_BUTTON_RECT_WH = 100;
const DIGITALPSD_BUTTON_RECT_HH = 50;

@Component
export default struct NumKeyBoard {
  @Link themeType: number;
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
                  if (item.value === Constants.callPhone ||
                  item.value === Constants.goBack ||
                  item.value === Constants.delPwd) {
                    Text(item.row1)
                      .fontSize($r('app.float.digitalpsd_prompt_fontsize'))
                      .fontWeight(FontWeight.Medium)
                      .fontColor(this.themeType === 1 ? Color.Black : Color.White)
                      .textAlign(TextAlign.Center)
                      .width(Constants.fullContainerWidth)
                      .padding(0)
                      .margin(0)
                  } else {
                    Text(item.row1)
                      .fontSize($r('app.float.digitalpsd_row1_fontsize'))
                      .fontWeight(FontWeight.Medium)
                      .fontColor(this.themeType === 1 ? Color.Black : Color.White)
                      .textAlign(TextAlign.Center)
                      .width(Constants.fullContainerWidth)
                      .padding(0)
                      .margin(0)
                  }
                  if (!!item.row2) {
                    Text(item.row2)
                      .fontSize($r('app.float.digitalpsd_row2_fontsize'))
                      .fontWeight(FontWeight.Regular)
                      .fontColor(this.themeType === 1 ? Color.Black : Color.White)
                      .opacity($r('app.float.numkeyBoard_text_opacity'))
                      .textAlign(TextAlign.Center)
                      .width(Constants.fullContainerWidth)
                      .padding(0)
                      .margin(0)
                  }
                }
                .width(Constants.fullContainerWidth)
                .height('120px')
              }

              if (deviceInfo.deviceType === 'tablet') {
                if (item.value === Constants.callPhone ||
                item.value === Constants.goBack ||
                item.value === Constants.delPwd) {
                  Column() {
                    Button({ type: ButtonType.Normal, stateEffect: true })
                      .backgroundColor('#00FFFFFF')
                      .width(DIGITALPSD_BUTTON_RECT_WH)
                      .height(DIGITALPSD_BUTTON_RECT_HH)
                  }
                } else {
                  Column() {
                    Button({ type: ButtonType.Circle })
                      .backgroundColor('#00FFFFFF')
                      .width(DIGITALPSD_BUTTON_DIAMETER)
                      .height(DIGITALPSD_BUTTON_DIAMETER)
                  }
                }
              }
            }
            .onClick(() => {
              setTimeout(this.onKeyPress.bind(this), 0, item.index, () => {
              });
            })
            .id('numKeyBord_customPwd')
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