import UIKit
import FamilyControls
import DeviceActivity

/**
 * TimeLimitViewController
 * Allows parents to set specific time limits for selected applications
 */
class TimeLimitViewController: UIViewController {
    
    // UI Components
    private var tableView: UITableView!
    private var saveButton: UIButton!
    private var weeklyLimitSwitch: UISwitch!
    private var weeklyLimitLabel: UILabel!
    private var weekdayLimitSwitch: UISwitch!
    private var weekdayLimitLabel: UILabel!
    private var weekendLimitSwitch: UISwitch!
    private var weekendLimitLabel: UILabel!
    
    // Data
    private var apps: [AppInfo]
    private var timeLimits: [String: Int] = [:] // App name to minutes mapping
    private var useWeeklyLimit = false
    private var useWeekdayLimit = false
    private var useWeekendLimit = false
    
    init(apps: [AppInfo]) {
        self.apps = apps
        super.init(nibName: nil, bundle: nil)
        
        // Initialize time limits with default values
        for app in apps {
            timeLimits[app.name] = 60 // Default 60 minutes
        }
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        title = "u8bbeu7f6eu65f6u95f4u9650u5236"
        setupUI()
    }
    
    // MARK: - Private Methods
    
    private func setupUI() {
        view.backgroundColor = .systemBackground
        
        // Setup limit type switches section
        let switchesContainer = UIView()
        switchesContainer.translatesAutoresizingMaskIntoConstraints = false
        switchesContainer.backgroundColor = .secondarySystemBackground
        switchesContainer.layer.cornerRadius = 10
        view.addSubview(switchesContainer)
        
        // Weekly limit switch
        weeklyLimitLabel = UILabel()
        weeklyLimitLabel.text = "u6bcfu5468u9650u5236"
        weeklyLimitLabel.font = UIFont.systemFont(ofSize: 16)
        weeklyLimitLabel.translatesAutoresizingMaskIntoConstraints = false
        switchesContainer.addSubview(weeklyLimitLabel)
        
        weeklyLimitSwitch = UISwitch()
        weeklyLimitSwitch.translatesAutoresizingMaskIntoConstraints = false
        weeklyLimitSwitch.addTarget(self, action: #selector(weeklySwitchChanged), for: .valueChanged)
        switchesContainer.addSubview(weeklyLimitSwitch)
        
        // Weekday limit switch
        weekdayLimitLabel = UILabel()
        weekdayLimitLabel.text = "u5de5u4f5cu65e5u9650u5236"
        weekdayLimitLabel.font = UIFont.systemFont(ofSize: 16)
        weekdayLimitLabel.translatesAutoresizingMaskIntoConstraints = false
        switchesContainer.addSubview(weekdayLimitLabel)
        
        weekdayLimitSwitch = UISwitch()
        weekdayLimitSwitch.translatesAutoresizingMaskIntoConstraints = false
        weekdayLimitSwitch.addTarget(self, action: #selector(weekdaySwitchChanged), for: .valueChanged)
        switchesContainer.addSubview(weekdayLimitSwitch)
        
        // Weekend limit switch
        weekendLimitLabel = UILabel()
        weekendLimitLabel.text = "u5468u672bu9650u5236"
        weekendLimitLabel.font = UIFont.systemFont(ofSize: 16)
        weekendLimitLabel.translatesAutoresizingMaskIntoConstraints = false
        switchesContainer.addSubview(weekendLimitLabel)
        
        weekendLimitSwitch = UISwitch()
        weekendLimitSwitch.translatesAutoresizingMaskIntoConstraints = false
        weekendLimitSwitch.addTarget(self, action: #selector(weekendSwitchChanged), for: .valueChanged)
        switchesContainer.addSubview(weekendLimitSwitch)
        
        // Setup table view
        tableView = UITableView(frame: .zero, style: .insetGrouped)
        tableView.delegate = self
        tableView.dataSource = self
        tableView.register(TimeLimitCell.self, forCellReuseIdentifier: "TimeLimitCell")
        tableView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(tableView)
        
        // Setup save button
        saveButton = UIButton(type: .system)
        saveButton.setTitle("u4fddu5b58u8bbeu7f6e", for: .normal)
        saveButton.titleLabel?.font = UIFont.systemFont(ofSize: 18, weight: .medium)
        saveButton.backgroundColor = .systemBlue
        saveButton.setTitleColor(.white, for: .normal)
        saveButton.layer.cornerRadius = 10
        saveButton.addTarget(self, action: #selector(saveTapped), for: .touchUpInside)
        saveButton.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(saveButton)
        
        // Setup constraints
        NSLayoutConstraint.activate([
            switchesContainer.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 20),
            switchesContainer.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 20),
            switchesContainer.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -20),
            
            weeklyLimitLabel.topAnchor.constraint(equalTo: switchesContainer.topAnchor, constant: 16),
            weeklyLimitLabel.leadingAnchor.constraint(equalTo: switchesContainer.leadingAnchor, constant: 16),
            
            weeklyLimitSwitch.centerYAnchor.constraint(equalTo: weeklyLimitLabel.centerYAnchor),
            weeklyLimitSwitch.trailingAnchor.constraint(equalTo: switchesContainer.trailingAnchor, constant: -16),
            
            weekdayLimitLabel.topAnchor.constraint(equalTo: weeklyLimitLabel.bottomAnchor, constant: 20),
            weekdayLimitLabel.leadingAnchor.constraint(equalTo: switchesContainer.leadingAnchor, constant: 16),
            
            weekdayLimitSwitch.centerYAnchor.constraint(equalTo: weekdayLimitLabel.centerYAnchor),
            weekdayLimitSwitch.trailingAnchor.constraint(equalTo: switchesContainer.trailingAnchor, constant: -16),
            
            weekendLimitLabel.topAnchor.constraint(equalTo: weekdayLimitLabel.bottomAnchor, constant: 20),
            weekendLimitLabel.leadingAnchor.constraint(equalTo: switchesContainer.leadingAnchor, constant: 16),
            weekendLimitLabel.bottomAnchor.constraint(equalTo: switchesContainer.bottomAnchor, constant: -16),
            
            weekendLimitSwitch.centerYAnchor.constraint(equalTo: weekendLimitLabel.centerYAnchor),
            weekendLimitSwitch.trailingAnchor.constraint(equalTo: switchesContainer.trailingAnchor, constant: -16),
            
            tableView.topAnchor.constraint(equalTo: switchesContainer.bottomAnchor, constant: 20),
            tableView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            tableView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            tableView.bottomAnchor.constraint(equalTo: saveButton.topAnchor, constant: -20),
            
            saveButton.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 20),
            saveButton.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -20),
            saveButton.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -20),
            saveButton.heightAnchor.constraint(equalToConstant: 50)
        ])
    }
    
    // MARK: - Action Methods
    
    @objc private func weeklySwitchChanged(_ sender: UISwitch) {
        useWeeklyLimit = sender.isOn
        tableView.reloadData()
    }
    
    @objc private func weekdaySwitchChanged(_ sender: UISwitch) {
        useWeekdayLimit = sender.isOn
        tableView.reloadData()
    }
    
    @objc private func weekendSwitchChanged(_ sender: UISwitch) {
        useWeekendLimit = sender.isOn
        tableView.reloadData()
    }
    
    @objc private func saveTapped() {
        // Here we would save all the time limit settings
        // In a real app, this would interact with ScreenTimeManager to apply limits
        
        // Apply the limits via ScreenTimeManager
        for (appName, minutes) in timeLimits {
            // This is where we'd call the ScreenTimeManager to set actual limits
            print("Setting \(minutes) minute limit for \(appName)")
        }
        
        // Show success alert
        let alert = UIAlertController(
            title: "u6210u529f",
            message: "u65f6u95f4u9650u5236u8bbeu7f6eu5df2u4fddu5b58",
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: "u786eu5b9a", style: .default) { _ in
            self.navigationController?.popToRootViewController(animated: true)
        })
        present(alert, animated: true)
    }
    
    @objc private func sliderValueChanged(_ sender: UISlider) {
        // Find which cell's slider was changed
        guard let cell = sender.superview?.superview as? TimeLimitCell,
              let indexPath = tableView.indexPath(for: cell) else {
            return
        }
        
        // Update the time limit for this app
        let app = apps[indexPath.row]
        let minutes = Int(sender.value)
        timeLimits[app.name] = minutes
        
        // Update the label in the cell
        cell.updateTimeLabel(minutes: minutes)
    }
}

// MARK: - UITableViewDelegate & UITableViewDataSource

extension TimeLimitViewController: UITableViewDelegate, UITableViewDataSource {
    func numberOfSections(in tableView: UITableView) -> Int {
        if !useWeeklyLimit && !useWeekdayLimit && !useWeekendLimit {
            return 1 // Default section
        }
        
        var sectionCount = 0
        if useWeeklyLimit { sectionCount += 1 }
        if useWeekdayLimit { sectionCount += 1 }
        if useWeekendLimit { sectionCount += 1 }
        return sectionCount
    }
    
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return apps.count
    }
    
    func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        if !useWeeklyLimit && !useWeekdayLimit && !useWeekendLimit {
            return "u6bcfu65e5u65f6u95f4u9650u5236" // Default
        }
        
        var sections: [String] = []
        if useWeeklyLimit { sections.append("u6bcfu5468u9650u5236") }
        if useWeekdayLimit { sections.append("u5de5u4f5cu65e5u9650u5236") }
        if useWeekendLimit { sections.append("u5468u672bu9650u5236") }
        
        return sections[safe: section]
    }
    
    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        guard let cell = tableView.dequeueReusableCell(withIdentifier: "TimeLimitCell", for: indexPath) as? TimeLimitCell else {
            return UITableViewCell()
        }
        
        let app = apps[indexPath.row]
        let timeLimit = timeLimits[app.name] ?? 60
        cell.configure(with: app, timeLimit: timeLimit)
        cell.timeSlider.addTarget(self, action: #selector(sliderValueChanged), for: .valueChanged)
        return cell
    }
}

// MARK: - TimeLimitCell

class TimeLimitCell: UITableViewCell {
    private let appIconView = UIImageView()
    private let appNameLabel = UILabel()
    let timeSlider = UISlider()
    private let timeLabel = UILabel()
    
    override init(style: UITableViewCell.CellStyle, reuseIdentifier: String?) {
        super.init(style: style, reuseIdentifier: reuseIdentifier)
        setupViews()
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    private func setupViews() {
        selectionStyle = .none
        
        // App icon setup
        appIconView.translatesAutoresizingMaskIntoConstraints = false
        appIconView.contentMode = .scaleAspectFit
        contentView.addSubview(appIconView)
        
        // App name label setup
        appNameLabel.translatesAutoresizingMaskIntoConstraints = false
        appNameLabel.font = UIFont.systemFont(ofSize: 16)
        contentView.addSubview(appNameLabel)
        
        // Time slider setup
        timeSlider.translatesAutoresizingMaskIntoConstraints = false
        timeSlider.minimumValue = 15 // 15 minutes minimum
        timeSlider.maximumValue = 240 // 4 hours maximum
        timeSlider.value = 60 // Default 1 hour
        contentView.addSubview(timeSlider)
        
        // Time label setup
        timeLabel.translatesAutoresizingMaskIntoConstraints = false
        timeLabel.font = UIFont.systemFont(ofSize: 14)
        timeLabel.textAlignment = .right
        contentView.addSubview(timeLabel)
        
        // Constraints
        NSLayoutConstraint.activate([
            appIconView.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 16),
            appIconView.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 12),
            appIconView.widthAnchor.constraint(equalToConstant: 40),
            appIconView.heightAnchor.constraint(equalToConstant: 40),
            
            appNameLabel.leadingAnchor.constraint(equalTo: appIconView.trailingAnchor, constant: 12),
            appNameLabel.centerYAnchor.constraint(equalTo: appIconView.centerYAnchor),
            appNameLabel.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -16),
            
            timeSlider.topAnchor.constraint(equalTo: appIconView.bottomAnchor, constant: 16),
            timeSlider.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 16),
            timeSlider.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -80),
            timeSlider.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -16),
            
            timeLabel.leadingAnchor.constraint(equalTo: timeSlider.trailingAnchor, constant: 8),
            timeLabel.centerYAnchor.constraint(equalTo: timeSlider.centerYAnchor),
            timeLabel.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -16),
            timeLabel.widthAnchor.constraint(equalToConstant: 60)
        ])
    }
    
    func configure(with app: AppInfo, timeLimit: Int) {
        appIconView.image = app.icon
        appNameLabel.text = app.name
        timeSlider.value = Float(timeLimit)
        updateTimeLabel(minutes: timeLimit)
    }
    
    func updateTimeLabel(minutes: Int) {
        let hours = minutes / 60
        let mins = minutes % 60
        
        if hours > 0 {
            timeLabel.text = "\(hours)h \(mins)m"
        } else {
            timeLabel.text = "\(mins)m"
        }
    }
}

// MARK: - Helper Extensions

extension Collection {
    /// Returns the element at the specified index if it is within bounds, otherwise nil.
    subscript(safe index: Index) -> Element? {
        return indices.contains(index) ? self[index] : nil
    }
}
