import UIKit
import FamilyControls
import ManagedSettings

/**
 * AppSelectionViewController
 * Allows parents to select which apps to manage and set time limits for them
 */
class AppSelectionViewController: UIViewController {
    
    // UI Components
    private var tableView: UITableView!
    private var continueButton: UIButton!
    
    // Data for available apps
    private var availableApps: [AppInfo] = []
    private var selectedApps: Set<String> = []
    
    override func viewDidLoad() {
        super.viewDidLoad()
        title = "u9009u62e9u5e94u7528"
        setupUI()
        loadAvailableApps()
    }
    
    // MARK: - Private Methods
    
    private func setupUI() {
        view.backgroundColor = .systemBackground
        
        // Setup table view
        tableView = UITableView(frame: .zero, style: .insetGrouped)
        tableView.delegate = self
        tableView.dataSource = self
        tableView.register(AppSelectionCell.self, forCellReuseIdentifier: "AppSelectionCell")
        tableView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(tableView)
        
        // Setup continue button
        continueButton = UIButton(type: .system)
        continueButton.setTitle("u7ee7u7eed", for: .normal)
        continueButton.titleLabel?.font = UIFont.systemFont(ofSize: 18, weight: .medium)
        continueButton.backgroundColor = .systemBlue
        continueButton.setTitleColor(.white, for: .normal)
        continueButton.layer.cornerRadius = 10
        continueButton.addTarget(self, action: #selector(continueTapped), for: .touchUpInside)
        continueButton.translatesAutoresizingMaskIntoConstraints = false
        continueButton.isEnabled = false
        view.addSubview(continueButton)
        
        // Setup constraints
        NSLayoutConstraint.activate([
            tableView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            tableView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            tableView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            tableView.bottomAnchor.constraint(equalTo: continueButton.topAnchor, constant: -20),
            
            continueButton.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 20),
            continueButton.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -20),
            continueButton.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -20),
            continueButton.heightAnchor.constraint(equalToConstant: 50)
        ])
    }
    
    private func loadAvailableApps() {
        // In a real app, this would fetch the actual list of installed apps using FamilyControls API
        // For demonstration, we'll add sample apps
        availableApps = [
            AppInfo(name: "u6e38u620fu5e94u75281", icon: UIImage(systemName: "gamecontroller")!, timeLimit: 0, timeUsed: 0),
            AppInfo(name: "u6e38u620fu5e94u75282", icon: UIImage(systemName: "gamecontroller.fill")!, timeLimit: 0, timeUsed: 0),
            AppInfo(name: "u793eu4ea4u5e94u75281", icon: UIImage(systemName: "message")!, timeLimit: 0, timeUsed: 0),
            AppInfo(name: "u793eu4ea4u5e94u75282", icon: UIImage(systemName: "bubble.left")!, timeLimit: 0, timeUsed: 0),
            AppInfo(name: "u5a31u4e50u5e94u75281", icon: UIImage(systemName: "tv")!, timeLimit: 0, timeUsed: 0),
            AppInfo(name: "u5a31u4e50u5e94u75282", icon: UIImage(systemName: "music.note")!, timeLimit: 0, timeUsed: 0),
            AppInfo(name: "u5b66u4e60u5e94u75281", icon: UIImage(systemName: "book")!, timeLimit: 0, timeUsed: 0),
            AppInfo(name: "u5b66u4e60u5e94u75282", icon: UIImage(systemName: "pencil")!, timeLimit: 0, timeUsed: 0)
        ]
        tableView.reloadData()
    }
    
    private func updateContinueButtonState() {
        continueButton.isEnabled = !selectedApps.isEmpty
        if continueButton.isEnabled {
            continueButton.backgroundColor = .systemBlue
        } else {
            continueButton.backgroundColor = .systemGray3
        }
    }
    
    // MARK: - Action Methods
    
    @objc private func continueTapped() {
        // Create a filtered list of selected apps
        let filteredApps = availableApps.filter { selectedApps.contains($0.name) }
        
        // Navigate to time limit setting screen
        let timeLimitVC = TimeLimitViewController(apps: filteredApps)
        navigationController?.pushViewController(timeLimitVC, animated: true)
    }
}

// MARK: - UITableViewDelegate & UITableViewDataSource

extension AppSelectionViewController: UITableViewDelegate, UITableViewDataSource {
    func numberOfSections(in tableView: UITableView) -> Int {
        return 1
    }
    
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return availableApps.count
    }
    
    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        guard let cell = tableView.dequeueReusableCell(withIdentifier: "AppSelectionCell", for: indexPath) as? AppSelectionCell else {
            return UITableViewCell()
        }
        
        let app = availableApps[indexPath.row]
        let isSelected = selectedApps.contains(app.name)
        cell.configure(with: app, isSelected: isSelected)
        return cell
    }
    
    func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)
        
        let app = availableApps[indexPath.row]
        if selectedApps.contains(app.name) {
            selectedApps.remove(app.name)
        } else {
            selectedApps.insert(app.name)
        }
        
        tableView.reloadRows(at: [indexPath], with: .automatic)
        updateContinueButtonState()
    }
    
    func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        return "u9009u62e9u8981u7ba1u7406u7684u5e94u7528"
    }
    
    func tableView(_ tableView: UITableView, titleForFooterInSection section: Int) -> String? {
        return "u70b9u51fbu9009u62e9u60a8u5e0cu671bu4e3au5b69u5b50u9650u5236u4f7fu7528u65f6u95f4u7684u5e94u7528u7a0bu5e8f"
    }
}

// MARK: - AppSelectionCell

class AppSelectionCell: UITableViewCell {
    private let appIconView = UIImageView()
    private let appNameLabel = UILabel()
    private let checkmarkView = UIImageView()
    
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
        appNameLabel.font = UIFont.systemFont(ofSize: 16)
        contentView.addSubview(appNameLabel)
        
        // Checkmark view setup
        checkmarkView.translatesAutoresizingMaskIntoConstraints = false
        checkmarkView.image = UIImage(systemName: "checkmark.circle.fill")
        checkmarkView.tintColor = .systemBlue
        checkmarkView.isHidden = true
        contentView.addSubview(checkmarkView)
        
        // Constraints
        NSLayoutConstraint.activate([
            appIconView.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 16),
            appIconView.centerYAnchor.constraint(equalTo: contentView.centerYAnchor),
            appIconView.widthAnchor.constraint(equalToConstant: 40),
            appIconView.heightAnchor.constraint(equalToConstant: 40),
            
            appNameLabel.leadingAnchor.constraint(equalTo: appIconView.trailingAnchor, constant: 12),
            appNameLabel.centerYAnchor.constraint(equalTo: contentView.centerYAnchor),
            appNameLabel.trailingAnchor.constraint(equalTo: checkmarkView.leadingAnchor, constant: -12),
            
            checkmarkView.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -16),
            checkmarkView.centerYAnchor.constraint(equalTo: contentView.centerYAnchor),
            checkmarkView.widthAnchor.constraint(equalToConstant: 24),
            checkmarkView.heightAnchor.constraint(equalToConstant: 24)
        ])
    }
    
    func configure(with app: AppInfo, isSelected: Bool) {
        appIconView.image = app.icon
        appNameLabel.text = app.name
        checkmarkView.isHidden = !isSelected
    }
}
