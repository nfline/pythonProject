import UIKit
import Charts

/**
 * UsageReportViewController
 * Displays detailed usage reports and analytics about children's app usage
 */
class UsageReportViewController: UIViewController {
    
    // UI Components
    private var segmentedControl: UISegmentedControl!
    private var chartView: UIView!
    private var tableView: UITableView!
    
    // Time period options
    private let timeOptions = ["u4ecau5929", "u672cu5468", "u672cu6708"]
    
    // Current selected time period
    private var selectedTimePeriod = 0
    
    // Sample usage data - in a real app this would come from ScreenTimeManager
    private var usageData: [AppUsageData] = [
        AppUsageData(appName: "u6e38u620fu5e94u75281", usageTime: 45, icon: UIImage(systemName: "gamecontroller")!),
        AppUsageData(appName: "u793eu4ea4u5e94u75281", usageTime: 30, icon: UIImage(systemName: "message")!),
        AppUsageData(appName: "u5b66u4e60u5e94u75281", usageTime: 60, icon: UIImage(systemName: "book")!),
        AppUsageData(appName: "u5a31u4e50u5e94u75281", usageTime: 20, icon: UIImage(systemName: "tv")!),
        AppUsageData(appName: "u6e38u620fu5e94u75282", usageTime: 15, icon: UIImage(systemName: "gamecontroller.fill")!)
    ]
    
    // Weekly data for chart
    private let weeklyData: [[Int]] = [
        [45, 40, 60, 30, 50, 25, 55], // Game App 1
        [30, 25, 30, 40, 20, 15, 35], // Social App 1
        [60, 70, 45, 65, 55, 40, 50], // Education App 1
        [20, 15, 25, 10, 30, 20, 15], // Entertainment App 1
        [15, 20, 10, 15, 10, 30, 20]  // Game App 2
    ]
    
    override func viewDidLoad() {
        super.viewDidLoad()
        title = "u4f7fu7528u62a5u544a"
        setupUI()
        loadData()
    }
    
    // MARK: - Private Methods
    
    private func setupUI() {
        view.backgroundColor = .systemBackground
        
        // Setup segmented control for time period selection
        segmentedControl = UISegmentedControl(items: timeOptions)
        segmentedControl.selectedSegmentIndex = 0
        segmentedControl.addTarget(self, action: #selector(timeSegmentChanged), for: .valueChanged)
        segmentedControl.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(segmentedControl)
        
        // Setup chart view container
        chartView = UIView()
        chartView.backgroundColor = .secondarySystemBackground
        chartView.layer.cornerRadius = 10
        chartView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(chartView)
        
        // Setup table view for detailed app usage
        tableView = UITableView(frame: .zero, style: .plain)
        tableView.delegate = self
        tableView.dataSource = self
        tableView.register(UsageReportCell.self, forCellReuseIdentifier: "UsageReportCell")
        tableView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(tableView)
        
        // Setup constraints
        NSLayoutConstraint.activate([
            segmentedControl.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 20),
            segmentedControl.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 20),
            segmentedControl.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -20),
            
            chartView.topAnchor.constraint(equalTo: segmentedControl.bottomAnchor, constant: 20),
            chartView.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 20),
            chartView.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -20),
            chartView.heightAnchor.constraint(equalTo: view.heightAnchor, multiplier: 0.35),
            
            tableView.topAnchor.constraint(equalTo: chartView.bottomAnchor, constant: 20),
            tableView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            tableView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            tableView.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor)
        ])
        
        // Initial chart setup
        setupChart()
    }
    
    private func loadData() {
        // In a real app, this would load actual usage data from ScreenTimeManager
        // For now, we'll use our sample data
        
        // Sort by usage time (descending)
        usageData.sort { $0.usageTime > $1.usageTime }
        tableView.reloadData()
    }
    
    private func setupChart() {
        // Note: In a real app, you would use a charting library like Charts
        // Here we'll create a simple visual representation
        
        // Clear existing subviews
        chartView.subviews.forEach { $0.removeFromSuperview() }
        
        // Add chart title
        let titleLabel = UILabel()
        titleLabel.text = "u5e94u7528u4f7fu7528u65f6u95f4u5206u5e03"
        titleLabel.font = UIFont.systemFont(ofSize: 18, weight: .medium)
        titleLabel.textAlignment = .center
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        chartView.addSubview(titleLabel)
        
        // Calculate total usage time
        let totalUsage = usageData.reduce(0) { $0 + $1.usageTime }
        
        // Create simple bar chart
        let chartContainer = UIView()
        chartContainer.translatesAutoresizingMaskIntoConstraints = false
        chartView.addSubview(chartContainer)
        
        // Set up constraints for title and chart container
        NSLayoutConstraint.activate([
            titleLabel.topAnchor.constraint(equalTo: chartView.topAnchor, constant: 16),
            titleLabel.leadingAnchor.constraint(equalTo: chartView.leadingAnchor),
            titleLabel.trailingAnchor.constraint(equalTo: chartView.trailingAnchor),
            
            chartContainer.topAnchor.constraint(equalTo: titleLabel.bottomAnchor, constant: 16),
            chartContainer.leadingAnchor.constraint(equalTo: chartView.leadingAnchor, constant: 16),
            chartContainer.trailingAnchor.constraint(equalTo: chartView.trailingAnchor, constant: -16),
            chartContainer.bottomAnchor.constraint(equalTo: chartView.bottomAnchor, constant: -16)
        ])
        
        // Create bars for each app
        var previousBarView: UIView? = nil
        let barHeight: CGFloat = 30
        let spacing: CGFloat = 16
        
        for (index, appData) in usageData.enumerated() {
            // Container for this bar
            let barContainer = UIView()
            barContainer.translatesAutoresizingMaskIntoConstraints = false
            chartContainer.addSubview(barContainer)
            
            // App icon
            let iconView = UIImageView(image: appData.icon)
            iconView.contentMode = .scaleAspectFit
            iconView.translatesAutoresizingMaskIntoConstraints = false
            barContainer.addSubview(iconView)
            
            // App name label
            let nameLabel = UILabel()
            nameLabel.text = appData.appName
            nameLabel.font = UIFont.systemFont(ofSize: 14)
            nameLabel.translatesAutoresizingMaskIntoConstraints = false
            barContainer.addSubview(nameLabel)
            
            // Bar view (filled portion)
            let barView = UIView()
            barView.backgroundColor = self.barColor(forIndex: index)
            barView.layer.cornerRadius = 4
            barView.translatesAutoresizingMaskIntoConstraints = false
            barContainer.addSubview(barView)
            
            // Time label
            let timeLabel = UILabel()
            timeLabel.text = "\(appData.usageTime) min"
            timeLabel.font = UIFont.systemFont(ofSize: 12)
            timeLabel.textAlignment = .right
            timeLabel.translatesAutoresizingMaskIntoConstraints = false
            barContainer.addSubview(timeLabel)
            
            // Calculate bar width based on proportion of total usage
            let proportion = CGFloat(appData.usageTime) / CGFloat(totalUsage)
            
            // Constraints for this bar set
            NSLayoutConstraint.activate([
                // Position relative to previous bar or top of container
                barContainer.topAnchor.constraint(equalTo: previousBarView?.bottomAnchor ?? chartContainer.topAnchor, constant: spacing),
                barContainer.leadingAnchor.constraint(equalTo: chartContainer.leadingAnchor),
                barContainer.trailingAnchor.constraint(equalTo: chartContainer.trailingAnchor),
                barContainer.heightAnchor.constraint(equalToConstant: barHeight),
                
                // Icon
                iconView.leadingAnchor.constraint(equalTo: barContainer.leadingAnchor),
                iconView.centerYAnchor.constraint(equalTo: barContainer.centerYAnchor),
                iconView.widthAnchor.constraint(equalToConstant: 24),
                iconView.heightAnchor.constraint(equalToConstant: 24),
                
                // Name label
                nameLabel.leadingAnchor.constraint(equalTo: iconView.trailingAnchor, constant: 8),
                nameLabel.centerYAnchor.constraint(equalTo: barContainer.centerYAnchor),
                nameLabel.widthAnchor.constraint(equalToConstant: 100),
                
                // Bar
                barView.leadingAnchor.constraint(equalTo: nameLabel.trailingAnchor, constant: 16),
                barView.centerYAnchor.constraint(equalTo: barContainer.centerYAnchor),
                barView.heightAnchor.constraint(equalToConstant: barHeight / 2),
                barView.widthAnchor.constraint(equalTo: chartContainer.widthAnchor, multiplier: proportion, constant: -150),
                
                // Time label
                timeLabel.leadingAnchor.constraint(equalTo: barView.trailingAnchor, constant: 8),
                timeLabel.centerYAnchor.constraint(equalTo: barContainer.centerYAnchor),
                timeLabel.trailingAnchor.constraint(equalTo: barContainer.trailingAnchor)
            ])
            
            previousBarView = barContainer
        }
        
        // Make the last bar adjust to bottom of container if needed
        if let lastBar = previousBarView {
            NSLayoutConstraint.activate([
                lastBar.bottomAnchor.constraint(lessThanOrEqualTo: chartContainer.bottomAnchor)
            ])
        }
    }
    
    private func barColor(forIndex index: Int) -> UIColor {
        // Return different colors for different app types
        let colors: [UIColor] = [
            .systemRed,
            .systemBlue,
            .systemGreen,
            .systemOrange,
            .systemPurple,
            .systemTeal,
            .systemIndigo,
            .systemYellow
        ]
        
        return colors[index % colors.count]
    }
    
    // MARK: - Action Methods
    
    @objc private func timeSegmentChanged(_ sender: UISegmentedControl) {
        selectedTimePeriod = sender.selectedSegmentIndex
        loadData()
        setupChart()
    }
}

// MARK: - UITableViewDelegate & UITableViewDataSource

extension UsageReportViewController: UITableViewDelegate, UITableViewDataSource {
    func numberOfSections(in tableView: UITableView) -> Int {
        return 1
    }
    
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return usageData.count
    }
    
    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        guard let cell = tableView.dequeueReusableCell(withIdentifier: "UsageReportCell", for: indexPath) as? UsageReportCell else {
            return UITableViewCell()
        }
        
        let appData = usageData[indexPath.row]
        cell.configure(with: appData, rank: indexPath.row + 1)
        return cell
    }
    
    func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        return "u5e94u7528u4f7fu7528u8be6u60c5"
    }
    
    func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)
        
        // In a real app, navigate to detailed usage report for this app
        let appData = usageData[indexPath.row]
        let detailVC = AppUsageDetailViewController(appData: appData)
        navigationController?.pushViewController(detailVC, animated: true)
    }
}

// MARK: - UsageReportCell

class UsageReportCell: UITableViewCell {
    private let rankLabel = UILabel()
    private let appIconView = UIImageView()
    private let appNameLabel = UILabel()
    private let usageTimeLabel = UILabel()
    
    override init(style: UITableViewCell.CellStyle, reuseIdentifier: String?) {
        super.init(style: style, reuseIdentifier: reuseIdentifier)
        setupViews()
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    private func setupViews() {
        // Rank label setup
        rankLabel.font = UIFont.systemFont(ofSize: 16, weight: .bold)
        rankLabel.textAlignment = .center
        rankLabel.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(rankLabel)
        
        // App icon setup
        appIconView.contentMode = .scaleAspectFit
        appIconView.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(appIconView)
        
        // App name label setup
        appNameLabel.font = UIFont.systemFont(ofSize: 16)
        appNameLabel.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(appNameLabel)
        
        // Usage time label setup
        usageTimeLabel.font = UIFont.systemFont(ofSize: 14)
        usageTimeLabel.textColor = .secondaryLabel
        usageTimeLabel.textAlignment = .right
        usageTimeLabel.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(usageTimeLabel)
        
        // Constraints
        NSLayoutConstraint.activate([
            rankLabel.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 16),
            rankLabel.centerYAnchor.constraint(equalTo: contentView.centerYAnchor),
            rankLabel.widthAnchor.constraint(equalToConstant: 24),
            
            appIconView.leadingAnchor.constraint(equalTo: rankLabel.trailingAnchor, constant: 12),
            appIconView.centerYAnchor.constraint(equalTo: contentView.centerYAnchor),
            appIconView.widthAnchor.constraint(equalToConstant: 32),
            appIconView.heightAnchor.constraint(equalToConstant: 32),
            
            appNameLabel.leadingAnchor.constraint(equalTo: appIconView.trailingAnchor, constant: 12),
            appNameLabel.centerYAnchor.constraint(equalTo: contentView.centerYAnchor),
            
            usageTimeLabel.leadingAnchor.constraint(equalTo: appNameLabel.trailingAnchor, constant: 12),
            usageTimeLabel.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -16),
            usageTimeLabel.centerYAnchor.constraint(equalTo: contentView.centerYAnchor),
            usageTimeLabel.widthAnchor.constraint(equalToConstant: 80)
        ])
    }
    
    func configure(with appData: AppUsageData, rank: Int) {
        rankLabel.text = "\(rank)"
        appIconView.image = appData.icon
        appNameLabel.text = appData.appName
        usageTimeLabel.text = "\(appData.usageTime) u5206u949f"
    }
}

// MARK: - AppUsageDetailViewController

class AppUsageDetailViewController: UIViewController {
    private let appData: AppUsageData
    
    init(appData: AppUsageData) {
        self.appData = appData
        super.init(nibName: nil, bundle: nil)
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        title = appData.appName
        view.backgroundColor = .systemBackground
        
        // In a real app, this would display detailed usage statistics
        // For now, we'll just show a placeholder
        let label = UILabel()
        label.text = "u8fd9u91ccu5c06u663eu793a \(appData.appName) u7684u8be6u7ec6u4f7fu7528u6570u636e"
        label.textAlignment = .center
        label.numberOfLines = 0
        label.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(label)
        
        NSLayoutConstraint.activate([
            label.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            label.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            label.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 20),
            label.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -20)
        ])
    }
}

// MARK: - Supporting Types

struct AppUsageData {
    let appName: String
    let usageTime: Int // in minutes
    let icon: UIImage
}
