import UIKit
import LocalAuthentication

/**
 * SettingsViewController
 * Allows parents to configure application settings, including password management
 */
class SettingsViewController: UIViewController {
    
    // UI Components
    private var tableView: UITableView!
    
    // Settings options
    private let settingsOptions = [
        ["changePassword", "resetPassword"], // Password section
        ["notifications", "autoLock"], // Notifications section
        ["about", "help", "privacyPolicy"] // App info section
    ]
    
    private let sectionTitles = [
        "密码管理",
        "通知设置",
        "应用信息"
    ]
    
    override func viewDidLoad() {
        super.viewDidLoad()
        title = "设置"
        setupUI()
    }
    
    // MARK: - Private Methods
    
    private func setupUI() {
        view.backgroundColor = .systemBackground
        
        // Setup table view
        tableView = UITableView(frame: .zero, style: .insetGrouped)
        tableView.delegate = self
        tableView.dataSource = self
        tableView.register(UITableViewCell.self, forCellReuseIdentifier: "SettingCell")
        tableView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(tableView)
        
        // Setup constraints
        NSLayoutConstraint.activate([
            tableView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            tableView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            tableView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            tableView.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor)
        ])
    }
    
    private func authenticateParent(completion: @escaping (Bool) -> Void) {
        let alertController = UIAlertController(
            title: "家长验证",
            message: "请输入家长密码以继续",
            preferredStyle: .alert
        )
        
        alertController.addTextField { textField in
            textField.placeholder = "密码"
            textField.isSecureTextEntry = true
        }
        
        let cancelAction = UIAlertAction(title: "取消", style: .cancel) { _ in
            completion(false)
        }
        
        let verifyAction = UIAlertAction(title: "验证", style: .default) { _ in
            if let password = alertController.textFields?.first?.text,
               CustomPasswordManager.shared.verifyPassword(password) {
                // Password is correct
                completion(true)
            } else {
                // Password is incorrect
                self.showErrorAlert(message: "密码不正确，请重试") { _ in
                    self.authenticateParent(completion: completion)
                }
            }
        }
        
        alertController.addAction(cancelAction)
        alertController.addAction(verifyAction)
        present(alertController, animated: true)
    }
    
    private func showPasswordChangeUI() {
        let alertController = UIAlertController(
            title: "更改家长密码",
            message: "请输入当前密码和新密码",
            preferredStyle: .alert
        )
        
        alertController.addTextField { textField in
            textField.placeholder = "当前密码"
            textField.isSecureTextEntry = true
        }
        
        alertController.addTextField { textField in
            textField.placeholder = "新密码"
            textField.isSecureTextEntry = true
        }
        
        alertController.addTextField { textField in
            textField.placeholder = "确认新密码"
            textField.isSecureTextEntry = true
        }
        
        let cancelAction = UIAlertAction(title: "取消", style: .cancel)
        
        let changeAction = UIAlertAction(title: "更改", style: .default) { _ in
            guard let currentPassword = alertController.textFields?[0].text,
                  let newPassword = alertController.textFields?[1].text,
                  let confirmPassword = alertController.textFields?[2].text,
                  !currentPassword.isEmpty,
                  !newPassword.isEmpty,
                  !confirmPassword.isEmpty else {
                self.showErrorAlert(message: "请填写所有密码字段")
                return
            }
            
            if newPassword != confirmPassword {
                self.showErrorAlert(message: "新密码不匹配")
                return
            }
            
            if CustomPasswordManager.shared.resetPassword(currentPassword: currentPassword, newPassword: newPassword) {
                self.showSuccessAlert(message: "密码已成功更改")
            } else {
                self.showErrorAlert(message: "当前密码不正确")
            }
        }
        
        alertController.addAction(cancelAction)
        alertController.addAction(changeAction)
        present(alertController, animated: true)
    }
    
    private func showPasswordResetUI() {
        // First confirm with biometric authentication
        let context = LAContext()
        var error: NSError?
        
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            let reason = "验证身份以重置家长控制密码"
            
            context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, error in
                DispatchQueue.main.async {
                    if success {
                        // Authentication successful, show reset UI
                        self.presentPasswordResetAlert()
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
            // Biometric authentication not available, use device passcode
            let reason = "验证身份以重置家长控制密码"
            
            context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, error in
                DispatchQueue.main.async {
                    if success {
                        // Authentication successful, show reset UI
                        self.presentPasswordResetAlert()
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
    
    private func presentPasswordResetAlert() {
        let alertController = UIAlertController(
            title: "重置密码",
            message: "请设置新的家长控制密码",
            preferredStyle: .alert
        )
        
        alertController.addTextField { textField in
            textField.placeholder = "新密码"
            textField.isSecureTextEntry = true
        }
        
        alertController.addTextField { textField in
            textField.placeholder = "确认密码"
            textField.isSecureTextEntry = true
        }
        
        let cancelAction = UIAlertAction(title: "取消", style: .cancel)
        
        let resetAction = UIAlertAction(title: "重置", style: .default) { _ in
            guard let newPassword = alertController.textFields?[0].text,
                  let confirmPassword = alertController.textFields?[1].text,
                  !newPassword.isEmpty,
                  !confirmPassword.isEmpty else {
                self.showErrorAlert(message: "请填写所有密码字段")
                return
            }
            
            if newPassword != confirmPassword {
                self.showErrorAlert(message: "密码不匹配")
                return
            }
            
            // First clear old password then set new one
            CustomPasswordManager.shared.emergencyReset { success in
                if success && CustomPasswordManager.shared.setPassword(newPassword) {
                    self.showSuccessAlert(message: "密码已成功重置")
                } else {
                    self.showErrorAlert(message: "密码重置失败，请重试")
                }
            }
        }
        
        alertController.addAction(cancelAction)
        alertController.addAction(resetAction)
        present(alertController, animated: true)
    }
    
    private func showNotificationSettings() {
        let notificationVC = NotificationSettingsViewController()
        navigationController?.pushViewController(notificationVC, animated: true)
    }
    
    private func showAutoLockSettings() {
        let autoLockVC = AutoLockSettingsViewController()
        navigationController?.pushViewController(autoLockVC, animated: true)
    }
    
    private func showAboutApp() {
        let alertController = UIAlertController(
            title: "关于应用",
            message: "智能屏幕时间管理 App\nVersion 1.0.0\n\n这款应用帮助家长更好地管理孩子的屏幕使用时间，通过设置时间限制保护孩子的健康。",
            preferredStyle: .alert
        )
        let okAction = UIAlertAction(title: "确定", style: .default)
        alertController.addAction(okAction)
        present(alertController, animated: true)
    }
    
    private func showHelpInfo() {
        let helpVC = HelpViewController()
        navigationController?.pushViewController(helpVC, animated: true)
    }
    
    private func showPrivacyPolicy() {
        let privacyVC = PrivacyPolicyViewController()
        navigationController?.pushViewController(privacyVC, animated: true)
    }
    
    private func showErrorAlert(message: String, completion: ((UIAlertAction) -> Void)? = nil) {
        let alertController = UIAlertController(
            title: "错误",
            message: message,
            preferredStyle: .alert
        )
        let okAction = UIAlertAction(title: "确定", style: .default, handler: completion)
        alertController.addAction(okAction)
        present(alertController, animated: true)
    }
    
    private func showSuccessAlert(message: String) {
        let alertController = UIAlertController(
            title: "成功",
            message: message,
            preferredStyle: .alert
        )
        let okAction = UIAlertAction(title: "确定", style: .default)
        alertController.addAction(okAction)
        present(alertController, animated: true)
    }
}

// MARK: - UITableViewDelegate & UITableViewDataSource

extension SettingsViewController: UITableViewDelegate, UITableViewDataSource {
    func numberOfSections(in tableView: UITableView) -> Int {
        return settingsOptions.count
    }
    
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return settingsOptions[section].count
    }
    
    func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        return sectionTitles[section]
    }
    
    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "SettingCell", for: indexPath)
        let option = settingsOptions[indexPath.section][indexPath.row]
        
        // Configure cell based on option
        switch option {
        case "changePassword":
            cell.textLabel?.text = "更改密码"
            cell.accessoryType = .disclosureIndicator
        case "resetPassword":
            cell.textLabel?.text = "重置密码"
            cell.accessoryType = .disclosureIndicator
        case "notifications":
            cell.textLabel?.text = "通知设置"
            cell.accessoryType = .disclosureIndicator
        case "autoLock":
            cell.textLabel?.text = "自动锁定设置"
            cell.accessoryType = .disclosureIndicator
        case "about":
            cell.textLabel?.text = "关于应用"
            cell.accessoryType = .disclosureIndicator
        case "help":
            cell.textLabel?.text = "帮助与支持"
            cell.accessoryType = .disclosureIndicator
        case "privacyPolicy":
            cell.textLabel?.text = "隐私政策"
            cell.accessoryType = .disclosureIndicator
        default:
            cell.textLabel?.text = option
        }
        
        return cell
    }
    
    func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)
        let option = settingsOptions[indexPath.section][indexPath.row]
        
        // Handle option selection
        switch option {
        case "changePassword":
            authenticateParent { success in
                if success {
                    self.showPasswordChangeUI()
                }
            }
        case "resetPassword":
            showPasswordResetUI()
        case "notifications":
            showNotificationSettings()
        case "autoLock":
            showAutoLockSettings()
        case "about":
            showAboutApp()
        case "help":
            showHelpInfo()
        case "privacyPolicy":
            showPrivacyPolicy()
        default:
            break
        }
    }
}

// MARK: - Placeholder View Controllers for Settings Sections

class NotificationSettingsViewController: UIViewController {
    override func viewDidLoad() {
        super.viewDidLoad()
        title = "通知设置"
        view.backgroundColor = .systemBackground
        
        // This would be implemented with actual notification settings
        let label = UILabel()
        label.text = "通知设置将在这里实现"
        label.textAlignment = .center
        label.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(label)
        
        NSLayoutConstraint.activate([
            label.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            label.centerYAnchor.constraint(equalTo: view.centerYAnchor)
        ])
    }
}

class AutoLockSettingsViewController: UIViewController {
    override func viewDidLoad() {
        super.viewDidLoad()
        title = "自动锁定设置"
        view.backgroundColor = .systemBackground
        
        // This would be implemented with actual auto-lock settings
        let label = UILabel()
        label.text = "自动锁定设置将在这里实现"
        label.textAlignment = .center
        label.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(label)
        
        NSLayoutConstraint.activate([
            label.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            label.centerYAnchor.constraint(equalTo: view.centerYAnchor)
        ])
    }
}

class HelpViewController: UIViewController {
    override func viewDidLoad() {
        super.viewDidLoad()
        title = "帮助与支持"
        view.backgroundColor = .systemBackground
        
        // This would be implemented with actual help content
        let label = UILabel()
        label.text = "帮助内容将在这里实现"
        label.textAlignment = .center
        label.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(label)
        
        NSLayoutConstraint.activate([
            label.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            label.centerYAnchor.constraint(equalTo: view.centerYAnchor)
        ])
    }
}

class PrivacyPolicyViewController: UIViewController {
    override func viewDidLoad() {
        super.viewDidLoad()
        title = "隐私政策"
        view.backgroundColor = .systemBackground
        
        // This would be implemented with actual privacy policy content
        let label = UILabel()
        label.text = "隐私政策内容将在这里实现"
        label.textAlignment = .center
        label.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(label)
        
        NSLayoutConstraint.activate([
            label.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            label.centerYAnchor.constraint(equalTo: view.centerYAnchor)
        ])
    }
}
