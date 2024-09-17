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

import * as core from '@actions/core'
import * as exec from '@actions/exec'
import * as github from '@actions/github'
import * as tc from '@actions/tool-cache'
import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'

import { BOOTSTRAP_VERSION, BOOTSTRAP_DIGEST } from './bootstrap'
import * as utils from './utils'

export const SLSA_REPO = 'https://github.com/slsa-framework/slsa-verifier'

export async function run(): Promise<void> {
  let tmpDir
  try {
    // System information
    const OS = utils.getOS(process.platform)
    const ARCH = utils.getArch(process.arch)
    const EXE = OS === 'windows' ? '.exe' : ''
    const BIN_NAME = `slsa-verifier${EXE}`
    const ARTIFACT_NAME = `slsa-verifier-${OS}-${ARCH}${EXE}`

    // Authenticate with GitHub
    const octokit = github.getOctokit(core.getInput('token'))

    // Validate requested version
    let version =
      core.getInput('version') ||
      process.env.GITHUB_ACTION_REF ||
      process.env.SLSA_VERIFIER_CI_ACTION_REF
    try {
      core.debug(`version => ${version}`)
      if (utils.isSha(version)) {
        version = await utils.getVersionReleaseBySha(version, octokit)
      } else if (utils.validVersion(version)) {
        version = await utils.getVersionRelease(version, octokit)
      } else if (version === 'latest') {
        version = await utils.getLatestVersion(octokit)
      } else throw Error
    } catch (error) {
      // If we get an error message, then something when wrong with a valid
      // version. If we get a blank error, that means we got an invalid version.
      const message = error instanceof Error ? error.message : ''
      if (message) {
        throw Error(
          `${message} - For a list of valid versions, see ${SLSA_REPO}/releases`
        )
      } else {
        throw Error(
          `Invalid version ${version} - For a list of valid versions, see ${SLSA_REPO}/releases`
        )
      }
    }
    core.info(`🏗️ Setting up slsa-verifier ${version}`)
    core.setOutput('version', version)

    // Create temp directory for downloading non-cached versions
    const cache = core.getInput('cache')
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'slsa-verifier_'))
    core.debug(`Created ${tmpDir}`)

    // Check if the bootstrap slsa-verifier is already in the tool-cache
    core.debug('Checking bootstrap slsa-verifier cache')
    let bootstrapPath = tc.find('slsa-verifier', BOOTSTRAP_VERSION.substring(1))

    // Load from cache if available, otherwise download it
    let bootstrapBin
    if (cache && bootstrapPath) {
      core.info('📥 Loaded bootstrap from runner cache')
      bootstrapBin = path.join(bootstrapPath, BIN_NAME)
    } else {
      // Download bootstrap slsa-verifier if not in cache or if cache is disabled
      core.info('⏬ Downloading bootstrap slsa-verifier')
      bootstrapBin = await utils.downloadReleaseArtifact(
        BOOTSTRAP_VERSION,
        ARTIFACT_NAME,
        path.join(path.join(tmpDir, 'bootstrap'), BIN_NAME)
      )
      fs.chmodSync(bootstrapBin, 0o755) // chmod +x
    }

    // Compare the SHA256 of the binary to the known expected value
    core.info('🔍 Verifying bootstrap slsa-verifier')
    const bootstrapDigest = utils.sha256File(bootstrapBin)
    core.debug(`bootstrapDigest => ${bootstrapDigest}`)
    if (BOOTSTRAP_DIGEST[OS][ARCH] !== bootstrapDigest) {
      throw Error('bootstrap slsa-verifier SHA256 verification failed')
    }
    core.info('✅ Verified bootstrap slsa-verifier')

    // Cache the bootstrap slsa-verifier download, but don't add it to PATH
    // In cases where cache=false, we still use this as the final location
    // but overwrite it each time. If we loaded from cache, don't re-cache it
    if (!cache || !bootstrapPath) {
      bootstrapPath = await tc.cacheFile(
        bootstrapBin,
        BIN_NAME,
        'slsa-verifier',
        BOOTSTRAP_VERSION.substring(1) // remove leading 'v'
      )

      // Manually update bootstrapBin because we don't add it to PATH
      bootstrapBin = path.join(bootstrapPath, BIN_NAME)
    }

    // If requested version is same as bootstrap then we can just use that
    // directly after verifying it's digest
    let mainPath
    if (version === BOOTSTRAP_VERSION) {
      core.info('📥 Loaded from bootstrap cache due to same version')
      mainPath = bootstrapPath
      core.setOutput('cache-hit', true)
    } else {
      // Check if the slsa-verifier is already in the tool-cache
      core.debug('Checking slsa-verifier cache')
      mainPath = tc.find('slsa-verifier', version.substring(1))
      core.setOutput('cache-hit', cache && !!mainPath)

      // Load from cache if available, otherwise download it
      let mainBin
      if (cache && mainPath) {
        core.info('📥 Loaded from runner cache')
        mainBin = path.join(mainPath, BIN_NAME)
      } else {
        // Download slsa-verifier if not in cache or if cache is disabled
        core.info('⏬ Downloading slsa-verifier')
        mainBin = await utils.downloadReleaseArtifact(
          version,
          ARTIFACT_NAME,
          path.join(path.join(tmpDir, version), BIN_NAME)
        )
        fs.chmodSync(mainBin, 0o755) // chmod +x
      }

      // Download slsa-verifier attestation next to main tool
      core.info('🔏 Downloading slsa-verifier attestation')
      const attestation = await utils.downloadReleaseArtifact(
        version,
        `${ARTIFACT_NAME}.intoto.jsonl`,
        `${mainBin}.intoto.jsonl`
      )

      // Run the bootstrap slsa-verifier against the version we wanted
      core.info('🔍 Verifying slsa-verifier')
      try {
        // This will exit 1 on error and display stdout and stderr automatically
        await exec.getExecOutput(bootstrapBin, [
          'verify-artifact',
          mainBin,
          '--provenance-path',
          attestation,
          '--source-uri',
          'github.com/slsa-framework/slsa-verifier',
          '--source-tag',
          version
        ])
      } catch (error) {
        core.debug(error instanceof Error ? error.message : (error as string))
        throw Error('slsa-verifier signature verification failed')
      }
      core.info('✅ Verified slsa-verifier')

      // Cache the slsa-verifier download
      // In cases where cache=false, we still use this as the final location
      // but overwrite it each time. If we loaded from cache, don't re-cache it
      if (!cache || !mainPath) {
        mainPath = await tc.cacheFile(
          mainBin,
          BIN_NAME,
          'slsa-verifier',
          version.substring(1) // remove leading 'v'
        )
      }
    }

    // Add the final slsa-verifier to our PATH
    core.addPath(mainPath)
    core.info('🎉 slsa-verifier is ready')
  } catch (error) {
    if (error instanceof Error) core.setFailed(error.message)
    else core.setFailed(error as string)
  }

  // Cleanup tmpDir if it was created at any point
  if (tmpDir) {
    core.debug(`Deleting ${tmpDir}`)
    fs.rmSync(tmpDir, { recursive: true, force: true })
  }
}
