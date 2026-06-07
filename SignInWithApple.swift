
import SwiftUI
import AuthenticationServices

// MARK: - Apple Sign In Button
struct AppleSignInButton: View {
    // ex: use this to dismiss input focus
    var prepareForAuthorization: () -> Void

    @State private var loading: Bool = false
    @State private var authorizationController = AppleAuthorizationController()

    var body: some View {
        // NOTE: Style doesn't match the JSX,
        // but Apple is really strict on the button UI to match their guideline
        ZStack {
            SignInWithAppleButton(
                .continue,
                onRequest: { _ in },
                onCompletion: { _ in }
            )
            .signInWithAppleButtonStyle(.white)
            .allowsHitTesting(false)

            Button(
                action: {
                    self.startAuthorization()
                },
                label: {
                    Rectangle()
                        .fill(Color.clear)
                        .contentShape(Rectangle())
                }
            )
            .buttonStyle(.plain)
            .accessibilityLabel("Sign in with Apple")

        }
        .frame(height: 58)
        .clipShape(RoundedRectangle(cornerRadius: 16))
        .shadow(color: .black.opacity(0.4), radius: 10, y: 2)
        .disabled(loading)
        .opacity(loading ? 0.6 : 1)
        .padding(.horizontal, 32)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(.black)
    }

    private func startAuthorization() {
        self.loading = true

        self.authorizationController.start(
            prepareForAuthorization: self.prepareForAuthorization,
            completion: { result in
                self.handleAuthorizationResult(result)
            }
        )
    }

    private func handleAuthorizationResult(
        _ result: Result<AppleSignInResult, Error>
    ) {
        defer {
            self.loading = false
        }
        switch result {
        case .failure(let error):
            if error as? AppleSignInError == .canceled {
                // do nothing.
            } else {
                // show error
            }

        case .success(let result):
            print(result)
            // for example, sign in with supabase.
            //    var session = try await self.supabaseClient.auth
            //        .signInWithIdToken(
            //            credentials: OpenIDConnectCredentials(
            //                provider: .apple,
            //                idToken: result.idToken,
            //                nonce: result.rawNonce
            //            )
            //        )
            break
        }
    }

}


enum AppleSignInError: LocalizedError, Equatable {
    case canceled
    case invalidCredential
    case missingNonce
    case missingAuthorizationCode
    case missingIdentityToken
    case missingPresentationAnchor
    case missingSupabaseService
    case unexpectedUser

    var errorDescription: String? {
        switch self {
        case .canceled:
            "Apple sign in was canceled."
        case .invalidCredential:
            "Apple returned an invalid credential."
        case .missingNonce:
            "Apple sign in could not verify the request nonce."
        case .missingAuthorizationCode:
            "Apple did not return an authorization code."
        case .missingIdentityToken:
            "Apple did not return an identity token."
        case .missingPresentationAnchor:
            "Apple Sign In could not find an active app window."
        case .missingSupabaseService:
            "Supabase is not configured for this app session."
        case .unexpectedUser:
            "Apple returned credentials for a different Apple account."
        }
    }
}


struct AppleSignInResult {
    let appleUserID: String
    let authorizationCode: String
    let idToken: String
    let rawNonce: String
    let fullName: PersonNameComponents?
}

final class AppleAuthorizationController: NSObject,
    ASAuthorizationControllerDelegate,
    ASAuthorizationControllerPresentationContextProviding
{
    func start(
        prepareForAuthorization: () -> Void,
        completion: @escaping (Result<AppleSignInResult, Error>) -> Void
    ) {
        prepareForAuthorization()

        guard let presentationAnchor = Self.keyPresentationAnchor else {
            completion(.failure(AppleSignInError.missingPresentationAnchor))
            return
        }

        self.completion = completion
        self.presentationAnchor = presentationAnchor

        let nonce = SignInNonce.make()
        currentNonce = nonce

        let request = ASAuthorizationAppleIDProvider().createRequest()
        request.requestedScopes = [.email, .fullName]
        request.nonce = SignInNonce.sha256(nonce)

        let controller = ASAuthorizationController(
            authorizationRequests: [request]
        )
        controller.delegate = self
        controller.presentationContextProvider = self
        controller.performRequests()
    }

    private var currentNonce: String?
    private var completion: ((Result<AppleSignInResult, Error>) -> Void)?
    private var presentationAnchor: ASPresentationAnchor?


    func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithAuthorization authorization: ASAuthorization
    ) {
        defer {
            currentNonce = nil
            completion = nil
        }

        guard let credential = authorization.credential
            as? ASAuthorizationAppleIDCredential
        else {
            completion?(.failure(AppleSignInError.invalidCredential))
            return
        }

        guard let rawNonce = currentNonce else {
            completion?(.failure(AppleSignInError.missingNonce))
            return
        }

        guard let idToken = credential.identityToken.flatMap({
            String(data: $0, encoding: .utf8)
        }) else {
            completion?(.failure(AppleSignInError.missingIdentityToken))
            return
        }

        guard let authorizationCode = credential.authorizationCode.flatMap({
            String(data: $0, encoding: .utf8)
        }) else {
            completion?(.failure(AppleSignInError.missingAuthorizationCode))
            return
        }

        completion?(
            .success(
                AppleSignInResult(
                    appleUserID: credential.user,
                    authorizationCode: authorizationCode,
                    idToken: idToken,
                    rawNonce: rawNonce,
                    fullName: credential.fullName
                )
            )
        )
    }

    func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithError error: Error
    ) {
        defer {
            currentNonce = nil
            completion = nil
        }

        if let authorizationError = error as? ASAuthorizationError,
            authorizationError.code == .canceled
        {
            completion?(.failure(AppleSignInError.canceled))
        } else {
            completion?(.failure(error))
        }
    }

    func presentationAnchor(
        for controller: ASAuthorizationController
    ) -> ASPresentationAnchor {
        guard let presentationAnchor else {
            preconditionFailure("Apple Sign In presentation anchor missing.")
        }
        return presentationAnchor
    }

    private static var keyPresentationAnchor: ASPresentationAnchor? {
        UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap(\.windows)
            .first { $0.isKeyWindow }
    }
}



import CryptoKit
import Foundation

enum SignInNonce {
    private static let charset = Array(
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-._"
    )

    static func make(length: Int = 32) -> String {
        var generator = SystemRandomNumberGenerator()

        return String(
            (0..<length).compactMap { _ in
                charset.randomElement(using: &generator)
            }
        )
    }

    static func sha256(_ input: String) -> String {
        let inputData = Data(input.utf8)
        let hashedData = SHA256.hash(data: inputData)

        return hashedData.map {
            String(format: "%02x", $0)
        }
        .joined()
    }
}
