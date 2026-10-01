// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "fuzzing/replay/file_util.h"

#include <cerrno>
#include <cstdio>
#include <filesystem>
#include <string>

#include "absl/functional/function_ref.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "fuzzing/replay/status_util.h"

namespace fuzzing {

absl::Status YieldFiles(
    absl::string_view path,
    absl::FunctionRef<void(absl::string_view,
                           const std::filesystem::file_status&)>
        callback) {
  std::error_code ec;

  if (std::filesystem::is_regular_file(path, ec)) {
    std::filesystem::file_status path_status =
        std::filesystem::status(path, ec);
    if (ec) {
      return absl::UnknownError(
          absl::StrCat("could not stat ", path, ": ", ec.message()));
    }

    callback(path, path_status);
    return absl::OkStatus();
  }

  std::filesystem::recursive_directory_iterator it{path, ec};
  if (ec) {
    return absl::UnknownError(
        absl::StrCat("could not stat ", path, ": ", ec.message()));
  }

  for (const auto& entry : it) {
    if (entry.is_directory(ec)) {
      continue;
    }

    const auto& entry_path = entry.path();

    std::filesystem::file_status path_status =
        std::filesystem::status(entry_path, ec);
    if (ec) {
      return absl::UnknownError(absl::StrCat(
          "could not stat ", entry_path.string(), ": ", ec.message()));
    }

    callback(entry_path.string(), path_status);
  }

  return absl::OkStatus();
}

absl::Status SetFileContents(absl::string_view path,
                             absl::string_view contents) {
  FILE* f = fopen(std::string(path).c_str(), "w");
  if (!f) {
    return ErrnoStatus("could not open file", errno);
  }
  const size_t result = fwrite(contents.data(), 1, contents.size(), f);
  fclose(f);
  if (result < contents.size()) {
    return absl::UnknownError("could not write file contents");
  }
  return absl::OkStatus();
}

}  // namespace fuzzing
