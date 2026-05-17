import SwiftUI

struct LoginView: View {
    @StateObject var viewModel: LoginViewModel
    let onLoginSuccess: () -> Void

    @FocusState private var focusedField: Field?

    enum Field {
        case serverUrl, username, password
    }

    var body: some View {
        VStack(spacing: 0) {
            Spacer()

            Text("旅迹定位")
                .font(.largeTitle)
                .fontWeight(.bold)

            Spacer()
                .frame(height: 48)

            VStack(spacing: 16) {
                TextField("服务器地址", text: $viewModel.uiState.serverUrl)
                    .textFieldStyle(.roundedBorder)
                    .textContentType(.URL)
                    .keyboardType(.URL)
                    .autocapitalization(.none)
                    .focused($focusedField, equals: .serverUrl)
                    .submitLabel(.next)
                    .onSubmit { focusedField = .username }
                    .disabled(viewModel.uiState.loading)

                TextField("用户名", text: $viewModel.uiState.username)
                    .textFieldStyle(.roundedBorder)
                    .textContentType(.username)
                    .focused($focusedField, equals: .username)
                    .submitLabel(.next)
                    .onSubmit { focusedField = .password }
                    .disabled(viewModel.uiState.loading)

                SecureField("密码", text: $viewModel.uiState.password)
                    .textFieldStyle(.roundedBorder)
                    .textContentType(.password)
                    .focused($focusedField, equals: .password)
                    .submitLabel(.done)
                    .onSubmit { login() }
                    .disabled(viewModel.uiState.loading)
            }

            if let error = viewModel.uiState.error {
                Text(error)
                    .font(.caption)
                    .foregroundColor(.red)
                    .padding(.top, 8)
            }

            Spacer()
                .frame(height: 24)

            Button(action: login) {
                HStack {
                    if viewModel.uiState.loading {
                        ProgressView()
                            .tint(.white)
                    }
                    Text("登录")
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 12)
            }
            .buttonStyle(.borderedProminent)
            .disabled(viewModel.uiState.loading || viewModel.uiState.username.isEmpty || viewModel.uiState.password.isEmpty)

            Spacer()
        }
        .padding(32)
        .onChange(of: viewModel.loginSuccess) { success in
            if success {
                onLoginSuccess()
            }
        }
    }

    private func login() {
        focusedField = nil
        viewModel.onLogin(navigateToMap: onLoginSuccess)
    }
}