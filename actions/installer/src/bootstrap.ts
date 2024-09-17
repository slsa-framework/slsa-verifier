/*
 * Copyright 2022 SLSA Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

export const BOOTSTRAP_VERSION = 'v2.6.0'
export const BOOTSTRAP_DIGEST: { [key: string]: { [key: string]: string } } = {
  darwin: {
    amd64: 'f838adf01bbe62b883e7967167fa827bbf7373f83e2d7727ec18e53f725fee93',
    arm64: '8740e66832fd48bbaa479acd5310986b876ff545460add0cb4a087aec056189c'
  },
  linux: {
    amd64: '1c9c0d6a272063f3def6d233fa3372adbaff1f5a3480611a07c744e73246b62d',
    arm64: '92b28eb2db998f9a6a048336928b29a38cb100076cd587e443ca0a2543d7c93d'
  },
  windows: {
    amd64: '37ca29ad748e8ea7be76d3ae766e8fa505362240431f6ea7f0648c727e2f2507',
    arm64: '6235daec8037a2e8f6aa11c583eed6b09b2cd36b61b43b9e5898281b39416d2f'
  }
}
