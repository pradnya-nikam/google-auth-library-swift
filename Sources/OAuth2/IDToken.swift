// Copyright 2019 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
import Foundation

let DEFAULT_EXPIRY_SECONDS: TimeInterval = 3600

public struct IDToken : Codable {
  public var idToken : String?
  public var creationTime : Date?
  enum CodingKeys: String, CodingKey {
    case idToken = "id_token"
    case creationTime = "creation_time"
  }

  func save(_ filename: String) throws {
    let encoder = JSONEncoder()
    let data = try encoder.encode(self)
    try data.write(to: URL(fileURLWithPath: filename))
  }

  public func isExpired() -> Bool {
    return timeToExpiry() <= 0
  }

  public func timeToExpiry() -> TimeInterval {
    guard let creationTime = creationTime else {
      return 0.0 // if we dont know when it expires, assume its expired
    }
    let expireDate = creationTime.addingTimeInterval(DEFAULT_EXPIRY_SECONDS)
    return expireDate.timeIntervalSinceNow
  }
}
