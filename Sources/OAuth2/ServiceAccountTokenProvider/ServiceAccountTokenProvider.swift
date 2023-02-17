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
#if canImport(FoundationNetworking)
  import FoundationNetworking
#endif

struct ServiceAccountCredentials : Codable {
  let CredentialType : String
  let ProjectId : String
  let PrivateKeyId : String
  let PrivateKey : String
  let ClientEmail : String
  let ClientID : String
  let AuthURI : String
  let TokenURI : String
  let AuthProviderX509CertURL : String
  let ClientX509CertURL : String
  enum CodingKeys: String, CodingKey {
    case CredentialType = "type"
    case ProjectId = "project_id"
    case PrivateKeyId = "private_key_id"
    case PrivateKey = "private_key"
    case ClientEmail = "client_email"
    case ClientID = "client_id"
    case AuthURI = "auth_uri"
    case TokenURI = "token_uri"
    case AuthProviderX509CertURL = "auth_provider_x509_cert_url"
    case ClientX509CertURL = "client_x509_cert_url"
  }
}

public class ServiceAccountTokenProvider : TokenProvider {
  public var token: Token?
  public var idToken: IDToken?
  var credentials : ServiceAccountCredentials
  var scopes : [String]
  var targetAudience: String?
  var rsaKey : RSAKey
  
  public init?(credentialsData:Data, scopes:[String], targetAudience: String? = nil) {
    let decoder = JSONDecoder()
    guard let credentials = try? decoder.decode(ServiceAccountCredentials.self,
                                                from: credentialsData)
      else {
        return nil
    }
    self.credentials = credentials
    self.scopes = scopes
    self.targetAudience = targetAudience
    guard let rsaKey = RSAKey(privateKey:credentials.PrivateKey)
      else {
        return nil
    }
    self.rsaKey = rsaKey
  }
  
  convenience public init?(credentialsURL:URL, scopes:[String], targetAudience: String? = nil) {
    guard let credentialsData = try? Data(contentsOf:credentialsURL, options:[]) else {
      return nil
    }
    self.init(credentialsData:credentialsData, scopes:scopes, targetAudience: targetAudience)
  }

  public func withToken(_ callback: @escaping (Token?, Error?) -> Void) throws {

    // leave spare at least one second :)
    if let token = token, token.timeToExpiry() > 1 {
      callback(token, nil)
      return
    }
    let urlRequest =  try createTokenRequest(assertion: generateAssertion(targetAudience: self.targetAudience, scope: scopes.joined(separator: " ")))

    let session = URLSession(configuration: URLSessionConfiguration.default)
    let task: URLSessionDataTask = session.dataTask(with:urlRequest)
    {(data, response, error) -> Void in
      if let data = data,
        let token = try? JSONDecoder().decode(Token.self, from: data) {
        self.token = token
        self.token?.CreationTime = Date()
        callback(self.token, error)
      } else {
        callback(nil, error)
      }
    }
    task.resume()
  }

  private func createTokenRequest(assertion: String) throws -> URLRequest {
    let json = ["grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": assertion]
    let data = try JSONSerialization.data(withJSONObject: json)

    var urlRequest = URLRequest(url:URL(string:credentials.TokenURI)!)
    urlRequest.httpMethod = "POST"
    urlRequest.httpBody = data
    urlRequest.setValue("application/json", forHTTPHeaderField:"Content-Type")
    return urlRequest
  }

  private func generateAssertion(targetAudience: String?, scope: String) throws -> String {
    let iat = Date()
    let exp = iat.addingTimeInterval(3600)
    let jwtClaimSet = JWTClaimSet(Issuer:credentials.ClientEmail,
                                  Audience:credentials.TokenURI,
                                  TargetAudience: targetAudience,
                                  Scope:  scope,
                                  IssuedAt: Int(iat.timeIntervalSince1970),
                                  Expiration: Int(exp.timeIntervalSince1970))
    let jwtHeader = JWTHeader(Algorithm: "RS256",
                              Format: "JWT")
    let msg = try JWT.encodeWithRS256(jwtHeader:jwtHeader,
                                      jwtClaimSet:jwtClaimSet,
                                      rsaKey:rsaKey)
    return msg
  }
}

extension ServiceAccountTokenProvider: IDTokenProvider {

  public func withIDToken(_ completion:@escaping (IDToken?, Error?) -> Void) throws {

    // leave spare at least one second :)
    if let idToken = idToken, idToken.timeToExpiry() > 1 {
      completion(idToken, nil)
      return
    }

    let urlRequest =  try createTokenRequest(assertion: generateAssertion(targetAudience: self.targetAudience, scope: scopes.joined(separator: " ")))

    let session = URLSession(configuration: URLSessionConfiguration.default)
    let task: URLSessionDataTask = session.dataTask(with: urlRequest)
    {(data, response, error) -> Void in
      if let data = data,
         let token = try? JSONDecoder().decode(IDToken.self, from: data) {
        self.idToken = token
        self.idToken?.creationTime = Date()
        completion(self.idToken, error)
      } else {
        completion(nil, error)
      }
    }
    task.resume()
  }
}
