import UIKit
import SwiftUI
import FamilyControls
import DeviceActivity

/**
 * ParentControlViewController
 * Main interface for parents to manage screen time limits and view usage reports
 */
class ParentControlViewController: UIViewController {
    
    // UI Components
    private var tableView: UITableView!
    private var addLimitButton: UIButton!
    private var reportButton: UIButton!
    private var settingsButton: UIButton!
    
    // Data source for app list
    private var managedApps: [AppInfo] = []
    
    override func viewDidLoad() {
        super.viewDidLoad()
        title = "家长控制面板"
        setupUI()
        loadManagedApps()
    }
    
    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        // Check if parent authentication is needed
        authenticateParent()
    }
    
    // MARK: - Private Methods
    
    private func setupUI() {
        view.backgroundColor = .systemBackground
        
        // Setup table view
        tableView = UITableView(frame: .zero, style: .insetGrouped)
        tableView.delegate = self
        tableView.dataSource = self
        tableView.register(AppLimitCell.self, forCellReuseIdentifier: "AppLimitCell")
        tableView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(tableView)
        
        // Setup add limit button
        addLimitButton = UIButton(type: .system)
        addLimitButton.setTitle("添加时间限制", for: .normal)
        addLimitButton.addTarget(self, action: #selector(addLimitTapped), for: .touchUpInside)
        addLimitButton.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(addLimitButton)
        
        // Setup report button
        reportButton = UIButton(type: .system)
        reportButton.setTitle("使用报告", for: .normal)
        reportButton.addTarget(self, action: #selector(reportTapped), for: .touchUpInside)
        reportButton.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(reportButton)
        
        // Setup settings button
        settingsButton = UIButton(type: .system)
        settingsButton.setTitle("设置", for: .normal)
        settingsButton.addTarget(self, action: #selector(settingsTapped), for: .touchUpInside)
        settingsButton.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(settingsButton)
        
        // Setup constraints
        NSLayoutConstraint.activate([
            tableView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            tableView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            tableView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            tableView.bottomAnchor.constraint(equalTo: addLimitButton.topAnchor, constant: -20),
            
            addLimitButton.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 20),
            addLimitButton.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -20),
            addLimitButton.heightAnchor.constraint(equalToConstant: 44),
            
            reportButton.leadingAnchor.constraint(equalTo: addLimitButton.trailingAnchor, constant: 20),
            reportButton.bottomAnchor.constraint(equalTo: addLimitButton.bottomAnchor),
            reportButton.heightAnchor.constraint(equalToConstant: 44),
            
            settingsButton.leadingAnchor.constraint(equalTo: reportButton.trailingAnchor, constant: 20),
            settingsButton.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -20),
            settingsButton.bottomAnchor.constraint(equalTo: addLimitButton.bottomAnchor),
            settingsButton.heightAnchor.constraint(equalToConstant: 44)
        ])
    }
    
    private func loadManagedApps() {
        // This would fetch the list of managed apps from the ScreenTimeManager
        // For demonstration, we'll add some sample apps
        managedApps = [
            AppInfo(name: "游戏应用1", icon: UIImage(systemName: "gamecontroller")!, timeLimit: 60, timeUsed: 45),
            AppInfo(name: "社交应用1", icon: UIImage(systemName: "message")!, timeLimit: 90, timeUsed: 30),
            AppInfo(name: "学习应用1", icon: UIImage(systemName: "book")!, timeLimit: 120, timeUsed: 60)
        ]
        tableView.reloadData()
    }
    
    private func authenticateParent() {
        // If no password is set, prompt to create one
        if !CustomPasswordManager.shared.hasPasswordSet() {
            presentPasswordSetupAlert()
            return
        }
        
        // Otherwise, verify the parent password
        let alertController = UIAlertController(
            title: "家长验证",
            message: "请输入家长密码以访问控制面板",
            preferredStyle: .alert
        )
        
        alertController.addTextField { textField in
            textField.placeholder = "密码"
            textField.isSecureTextEntry = true
        }
        
        let cancelAction = UIAlertAction(title: "取消", style: .cancel) { _ in
            // Go back if authentication is cancelled
            self.navigationController?.popViewController(animated: true)
        }
        
        let verifyAction = UIAlertAction(title: "验证", style: .default) { _ in
            if let password = alertController.textFields?.first?.text,
               CustomPasswordManager.shared.verifyPassword(password) {
                // Password is correct, continue to the screen
            } else {
                // Password is incorrect, show error and try again
                self.showErrorAlert(message: "密码不正确，请重试") { _ in
                    self.authenticateParent()
                }
            }
        }
        
        alertController.addAction(cancelAction)
        alertController.addAction(verifyAction)
        present(alertController, animated: true)
    }
    
    private func presentPasswordSetupAlert() {
        let alertController = UIAlertController(
            title: "设置家长密码",
            message: "请创建一个密码来保护家长控制设置",
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
        
        let cancelAction = UIAlertAction(title: "取消", style: .cancel) { _ in
            self.navigationController?.popViewController(animated: true)
        }
        
        let saveAction = UIAlertAction(title: "保存", style: .default) { _ in
            guard let password = alertController.textFields?[0].text,
                  let confirmPassword = alertController.textFields?[1].text,
                  !password.isEmpty else {
                self.showErrorAlert(message: "请输入有效的密码") { _ in
                    self.presentPasswordSetupAlert()
                }
                return
            }
            
            if password != confirmPassword {
                self.showErrorAlert(message: "密码不匹配，请重试") { _ in
                    self.presentPasswordSetupAlert()
                }
                return
            }
            
            if CustomPasswordManager.shared.setPassword(password) {
                self.showSuccessAlert(message: "密码设置成功")
            } else {
                self.showErrorAlert(message: "密码设置失败，请重试") { _ in
                    self.presentPasswordSetupAlert()
                }
            }
        }
        
        alertController.addAction(cancelAction)
        alertController.addAction(saveAction)
        present(alertController, animated: true)
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
    
    // MARK: - Action Methods
    
    @objc private func addLimitTapped() {
        // Present app selection and time limit setting UI
        let appSelectionVC = AppSelectionViewController()
        navigationController?.pushViewController(appSelectionVC, animated: true)
    }
    
    @objc private func reportTapped() {
        // Present usage reports UI
        let reportVC = UsageReportViewController()
        navigationController?.pushViewController(reportVC, animated: true)
    }
    
    @objc private func settingsTapped() {
        // Present settings UI
        let settingsVC = SettingsViewController()
        navigationController?.pushViewController(settingsVC, animated: true)
    }
}

// MARK: - UITableViewDelegate & UITableViewDataSource

extension ParentControlViewController: UITableViewDelegate, UITableViewDataSource {
    func numberOfSections(in tableView: UITableView) -> Int {
        return 1
    }
    
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return managedApps.count
    }
    
    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        guard let cell = tableView.dequeueReusableCell(withIdentifier: "AppLimitCell", for: indexPath) as? AppLimitCell else {
            return UITableViewCell()
        }
        
        let app = managedApps[indexPath.row]
        cell.configure(with: app)
        return cell
    }
    
    func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)
        let app = managedApps[indexPath.row]
        let editLimitVC = EditTimeViewController(app: app)
        navigationController?.pushViewController(editLimitVC, animated: true)
    }
    
    func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        return "受管理的应用"
    }
}

// MARK: - Supporting Types

struct AppInfo {
    let name: String
    let icon: UIImage
    var timeLimit: Int // in minutes
    var timeUsed: Int // in minutes
}

class AppLimitCell: UITableViewCell {
    private let appIconView = UIImageView()
    private let appNameLabel = UILabel()
    private let limitLabel = UILabel()
    private let progressView = UIProgressView(progressViewStyle: .default)
    
    override init(style: UITableViewCell.CellStyle, reuseIdentifier: String?) {
        super.init(style: style, reuseIdentifier: reuseIdentifier)
        setupViews()
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    private func setupViews() {
        // App icon setup
        appIconView.translatesAutoresizingMaskIntoConstraints = false
        appIconView.contentMode = .scaleAspectFit
        contentView.addSubview(appIconView)
        
        // App name label setup
        appNameLabel.translatesAutoresizingMaskIntoConstraints = false
        appNameLabel.font = UIFont.systemFont(ofSize: 16, weight: .medium)
        contentView.addSubview(appNameLabel)
        
        // Limit label setup
        limitLabel.translatesAutoresizingMaskIntoConstraints = false
        limitLabel.font = UIFont.systemFont(ofSize: 14)
        limitLabel.textColor = .secondaryLabel
        contentView.addSubview(limitLabel)
        
        // Progress view setup
        progressView.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(progressView)
        
        // Constraints
        NSLayoutConstraint.activate([
            appIconView.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 16),
            appIconView.centerYAnchor.constraint(equalTo: contentView.centerYAnchor),
            appIconView.widthAnchor.constraint(equalToConstant: 40),
            appIconView.heightAnchor.constraint(equalToConstant: 40),
            
            appNameLabel.leadingAnchor.constraint(equalTo: appIconView.trailingAnchor, constant: 12),
            appNameLabel.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 12),
            appNameLabel.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -16),
            
            limitLabel.leadingAnchor.constraint(equalTo: appNameLabel.leadingAnchor),
            limitLabel.topAnchor.constraint(equalTo: appNameLabel.bottomAnchor, constant: 4),
            limitLabel.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -16),
            
            progressView.leadingAnchor.constraint(equalTo: appNameLabel.leadingAnchor),
            progressView.topAnchor.constraint(equalTo: limitLabel.bottomAnchor, constant: 8),
            progressView.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -16),
            progressView.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -12)
        ])
    }
    
    func configure(with app: AppInfo) {
        appIconView.image = app.icon
        appNameLabel.text = app.name
        limitLabel.text = "已用 \(app.timeUsed)/\(app.timeLimit) 分钟"
        
        // Calculate and set progress
        let progress = Float(app.timeUsed) / Float(app.timeLimit)
        progressView.progress = progress
        
        // Change progress color based on usage percentage
        if progress < 0.5 {
            progressView.progressTintColor = .systemGreen
        } else if progress < 0.8 {
            progressView.progressTintColor = .systemYellow
        } else {
            progressView.progressTintColor = .systemRed
        }
    }
}
