// Copyright 2022 SLSA Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

const exec = require("@actions/exec");
const index = require("../lib/index");
const fs = require("fs");

describe("Test validVersion", function () {
  it("Accepts v0.0.1", function () {
    expect(index.validVersion("v1.0.0")).toBe(true);
  });
  it("Accepts v1.2.0", function () {
    expect(index.validVersion("v1.0.0")).toBe(true);
  });
  it("Rejects foobar", function () {
    expect(index.validVersion("foobar")).toBe(false);
  });
  it("Rejects commit hashes", function () {
    expect(
      index.validVersion(
        "1326430d044e8a9522c51e5f721e237b5f75acb6b4e518d129f669403cf7a79a"
      )
    ).toBe(false);
  });
});

describe("Test fileHasExpectedSha256Hash", function () {
  it("throws an error when the file does not exist", function () {
    expect(function () {
      index.fileHasExpectedSha256Hash("/path/to/nowhere", "12345");
    }).toThrow();
  });

  describe("Tests accessing real files", function () {
    beforeEach(function () {
      this.tmpDir = fs.mkdtempSync("jasmine");
      this.testFile = `${this.tmpDir}/testfile`;
      fs.writeFileSync(this.testFile, "test data");
    });

    afterEach(function () {
      fs.rmSync(this.tmpDir, { recursive: true });
    });

    it("Returns false when the computed and expected hashes don't match", function () {
      expect(index.fileHasExpectedSha256Hash(this.testFile, "foobar")).toBe(
        false
      );
    });
    it("Returns true when the computed and expected hashes don't match", function () {
      expect(
        index.fileHasExpectedSha256Hash(
          this.testFile,
          "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"
        )
      ).toBe(true);
    });
  });
});
