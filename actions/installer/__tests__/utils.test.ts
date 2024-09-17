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

import * as fs from 'fs'
import * as os from 'os'

import * as utils from '../src/utils'
import path from 'path'

describe('utils', () => {
  let tmpDir: string
  beforeAll(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'slsa-verifier-tests_'))
  })
  afterAll(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true })
  })

  describe('getArch', () => {
    test.each([
      ['x64', 'amd64'],
      ['arm64', 'arm64']
    ])('works for %s', async (arch, expected) => {
      const result = utils.getArch(arch)
      expect(result).toEqual(expected)
    })

    test.each([
      'arm',
      'ia32',
      'loong64',
      'mips',
      'mipsel',
      'ppc',
      'ppc64',
      'riscv64',
      's390',
      's390x'
    ])('errors on %s', async arch => {
      const result = (): string => utils.getArch(arch)
      expect(result).toThrow(`Unsupported architecture ${arch}`)
    })
  })

  describe('getOS', () => {
    test.each([
      ['win32', 'windows'],
      ['linux', 'linux'],
      ['darwin', 'darwin']
    ])('works for %s', async (platform, expected) => {
      const result = utils.getOS(platform)
      expect(result).toEqual(expected)
    })

    test.each(['aix', 'freebsd', 'openbsd', 'sunos'])(
      'errors on %s',
      async platform => {
        const result = (): string => utils.getOS(platform)
        expect(result).toThrow(`Unsupported OS ${platform}`)
      }
    )
  })

  describe('validVersion', () => {
    test.each(['v0.0.0', 'v1.0.0'])('accepts %s', async version => {
      const result = utils.validVersion(version)
      expect(result).toBeTruthy()
    })

    test.each([
      'latest',
      'foobar',
      '1.0.0',
      '57755b13f9c806ec4281bdb148fc6c6ed2d08726'
    ])('rejects %s', async version => {
      const result = utils.validVersion(version)
      expect(result).toBeFalsy()
    })
  })

  describe('isSha', () => {
    test('accepts 57755b13f9c806ec4281bdb148fc6c6ed2d08726', async () => {
      const sha = '57755b13f9c806ec4281bdb148fc6c6ed2d08726'
      const result = utils.isSha(sha)
      expect(result).toBeTruthy()
    })

    test.each(['foobar', '1.0.0', '1', '1.0', '57755b1'])(
      'rejects %s',
      async sha => {
        const result = utils.isSha(sha)
        expect(result).toBeFalsy()
      }
    )
  })

  describe('sha256File', () => {
    test('produces a proper hash', async () => {
      const file = path.join(tmpDir, 'testfile.txt')
      fs.writeFileSync(file, 'foobar')
      const expected =
        'c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2'
      const result = utils.sha256File(file)
      expect(result).toEqual(expected)
    })

    test('errors when file does not exist', async () => {
      const file =
        process.platform === 'win32'
          ? 'D:\\some\\invalid\\file'
          : '/some/invalid/file'
      const result = (): string => utils.sha256File(file)
      expect(result).toThrow(
        `ENOENT: no such file or directory, open '${file}'`
      )
    })
  })
})
