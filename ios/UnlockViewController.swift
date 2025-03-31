import UIKit
import LocalAuthentication

/**
 * UnlockViewController
 * Handles the unlock process when a child has reached time limits
 * Implements the secure password system that's separate from the iOS device passcode
 */
class UnlockViewController: UIViewController {
    
    // UI Components
    private var logoImageView: UIImageView!
    private var titleLabel: UILabel!
    private var messageLabel: UILabel!
    private var passwordTextField: UITextField!
    private var unlockButton: UIButton!
    private var emergencyButton: UIButton!
    
    // Callback when unlock is successful
    private var unlockCompletion: ((Bool) -> Void)?
    
    // App being unlocked
    private var appName: String
    
    // Authentication attempt counter
    private var attemptCount = 0
    private let maxAttempts = 5
    
    init(appName: String, completion: @escaping (Bool) -> Void) {
        self.appName = appName
        self.unlockCompletion = completion
        super.init(nibName: nil, bundle: nil)
        // Modal presentation style
        modalPresentationStyle = .fullScreen
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        setupUI()
    }
    
    // MARK: - Private Methods
    
    private func setupUI() {
        view.backgroundColor = .systemBackground
        
        // Logo image view
        logoImageView = UIImageView(image: UIImage(systemName: "lock.shield"))
        logoImageView.contentMode = .scaleAspectFit
        logoImageView.tintColor = .systemBlue
        logoImageView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(logoImageView)
        
        // Title label
        titleLabel = UILabel()
        titleLabel.text = "应用时间限制"
        titleLabel.font = UIFont.systemFont(ofSize: 24, weight: .bold)
        titleLabel.textAlignment = .center
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(titleLabel)
        
        // Message label
        messageLabel = UILabel()
        messageLabel.text = "\(appName) 已达到今日使用时间限制。请输入家长密码解锁。"
        messageLabel.font = UIFont.systemFont(ofSize: 16)
        messageLabel.textAlignment = .center
        messageLabel.numberOfLines = 0
        messageLabel.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(messageLabel)
        
        // Password text field
        passwordTextField = UITextField()
        passwordTextField.placeholder = "输入家长密码"
        passwordTextField.isSecureTextEntry = true
        passwordTextField.borderStyle = .roundedRect
        passwordTextField.translatesAutoresizingMaskIntoConstraints = false
        passwordTextField.delegate = self
        view.addSubview(passwordTextField)
        
        // Unlock button
        unlockButton = UIButton(type: .system)
        unlockButton.setTitle("解锁应用", for: .normal)
        unlockButton.titleLabel?.font = UIFont.systemFont(ofSize: 18, weight: .medium)
        unlockButton.backgroundColor = .systemBlue
        unlockButton.setTitleColor(.white, for: .normal)
        unlockButton.layer.cornerRadius = 10
        unlockButton.addTarget(self, action: #selector(unlockTapped), for: .touchUpInside)
        unlockButton.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(unlockButton)
        
        // Emergency unlock button
        emergencyButton = UIButton(type: .system)
        emergencyButton.setTitle("紧急解锁（家长）", for: .normal)
        emergencyButton.titleLabel?.font = UIFont.systemFont(ofSize: 14)
        emergencyButton.addTarget(self, action: #selector(emergencyTapped), for: .touchUpInside)
        emergencyButton.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(emergencyButton)
        
        // Setup constraints
        NSLayoutConstraint.activate([
            logoImageView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 60),
            logoImageView.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            logoImageView.widthAnchor.constraint(equalToConstant: 100),
            logoImageView.heightAnchor.constraint(equalToConstant: 100),
            
            titleLabel.topAnchor.constraint(equalTo: logoImageView.bottomAnchor, constant: 20),
            titleLabel.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 20),
            titleLabel.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -20),
            
            messageLabel.topAnchor.constraint(equalTo: titleLabel.bottomAnchor, constant: 16),
            messageLabel.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 40),
            messageLabel.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -40),
            
            passwordTextField.topAnchor.constraint(equalTo: messageLabel.bottomAnchor, constant: 40),
            passwordTextField.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 40),
            passwordTextField.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -40),
            passwordTextField.heightAnchor.constraint(equalToConstant: 50),
            
            unlockButton.topAnchor.constraint(equalTo: passwordTextField.bottomAnchor, constant: 30),
            unlockButton.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 40),
            unlockButton.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -40),
            unlockButton.heightAnchor.constraint(equalToConstant: 50),
            
            emergencyButton.topAnchor.constraint(equalTo: unlockButton.bottomAnchor, constant: 20),
            emergencyButton.centerXAnchor.constraint(equalTo: view.centerXAnchor)
        ])
    }
    
    // MARK: - Action Methods
    
    @objc private func unlockTapped() {
        guard let password = passwordTextField.text, !password.isEmpty else {
            showErrorAlert(message: "请输入密码")
            return
        }
        
        // Verify the password
        if CustomPasswordManager.shared.verifyPassword(password) {
            // Password is correct
            dismiss(animated: true) {
                self.unlockCompletion?(true)
            }
        } else {
            // Password is incorrect
            attemptCount += 1
            
            if attemptCount >= maxAttempts {
                // Too many attempts, show emergency unlock option
                showErrorAlert(message: "密码尝试次数过多。请使用紧急解锁选项。")
                passwordTextField.isEnabled = false
                unlockButton.isEnabled = false
            } else {
                // Show error with remaining attempts
                let remainingAttempts = maxAttempts - attemptCount
                showErrorAlert(message: "密码不正确。还剩 \(remainingAttempts) 次尝试机会。")
            }
            
            // Clear the password field
            passwordTextField.text = ""
        }
    }
    
    @objc private func emergencyTapped() {
        // Use biometric authentication for emergency unlock
        let context = LAContext()
        var error: NSError?
        
        // Check if biometric authentication is available
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            let reason = "验证家长身份以紧急解锁应用"
            
            context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, error in
                DispatchQueue.main.async {
                    if success {
                        // Authentication successful
                        self.dismiss(animated: true) {
                            self.unlockCompletion?(true)
                        }
                    } else {
                        // Authentication failed
                        if let error = error {
                            self.showErrorAlert(message: "验证失败：\(error.localizedDescription)")
                        } else {
                            self.showErrorAlert(message: "验证失败，请重试")
                        }
                    }
                }
            }
        } else {
            // Biometric authentication not available
            // Fall back to device passcode
            let reason = "验证设备密码以紧急解锁应用"
            
            context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, error in
                DispatchQueue.main.async {
                    if success {
                        // Authentication successful
                        self.dismiss(animated: true) {
                            self.unlockCompletion?(true)
                        }
                    } else {
                        // Authentication failed
                        if let error = error {
                            self.showErrorAlert(message: "验证失败：\(error.localizedDescription)")
                        } else {
                            self.showErrorAlert(message: "验证失败，请重试")
                        }
                    }
                }
            }
        }
    }
    
    private func showErrorAlert(message: String) {
        let alertController = UIAlertController(
            title: "错误",
            message: message,
            preferredStyle: .alert
        )
        let okAction = UIAlertAction(title: "确定", style: .default)
        alertController.addAction(okAction)
        present(alertController, animated: true)
    }
}

// MARK: - UITextFieldDelegate

extension UnlockViewController: UITextFieldDelegate {
    func textFieldShouldReturn(_ textField: UITextField) -> Bool {
        textField.resignFirstResponder()
        unlockTapped()
        return true
    }
}
