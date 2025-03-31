import Foundation
import CryptoKit
import LocalAuthentication

/**
 * CustomPasswordManager
 * Manages a secure password system separate from the iOS system passcode.
 * Provides secure storage, verification, and management of parental control passwords.
 */
class CustomPasswordManager {
    // Singleton pattern
    static let shared = CustomPasswordManager()
    
    // Keys for storing password data
    private let passwordHashKey = "com.screentimemanager.parentalPasswordHash"
    private let passwordSaltKey = "com.screentimemanager.parentalPasswordSalt"
    
    private let userDefaults = UserDefaults.standard
    
    private init() {}
    
    /**
     * Set a new parental control password
     * @returns Bool indicating success or failure
     */
    func setPassword(_ password: String) -> Bool {
        guard !password.isEmpty else {
            print("Password cannot be empty")
            return false
        }
        
        // Generate a random salt for this password
        let salt = generateRandomSalt()
        
        // Hash the password with the salt
        guard let passwordHash = hashPassword(password, withSalt: salt) else {
            return false
        }
        
        // Store the hash and salt securely
        userDefaults.set(passwordHash, forKey: passwordHashKey)
        userDefaults.set(salt, forKey: passwordSaltKey)
        
        return true
    }
    
    /**
     * Verify if the provided password is correct
     * @returns Bool indicating if the password is correct
     */
    func verifyPassword(_ password: String) -> Bool {
        guard !password.isEmpty else { return false }
        
        // Retrieve the stored hash and salt
        guard let storedHash = userDefaults.string(forKey: passwordHashKey),
              let salt = userDefaults.string(forKey: passwordSaltKey) else {
            print("No password has been set")
            return false
        }
        
        // Hash the provided password with the stored salt
        guard let computedHash = hashPassword(password, withSalt: salt) else {
            return false
        }
        
        // Compare the computed hash with the stored hash
        return computedHash == storedHash
    }
    
    /**
     * Check if a password has been set
     */
    func hasPasswordSet() -> Bool {
        return userDefaults.string(forKey: passwordHashKey) != nil
    }
    
    /**
     * Reset the password (requires current password verification)
     */
    func resetPassword(currentPassword: String, newPassword: String) -> Bool {
        guard verifyPassword(currentPassword) else {
            print("Current password is incorrect")
            return false
        }
        
        return setPassword(newPassword)
    }
    
    /**
     * Emergency reset mechanism using device biometrics
     */
    func emergencyReset(completion: @escaping (Bool) -> Void) {
        let context = LAContext()
        var error: NSError?
        
        // Check if biometric authentication is available
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            let reason = "Authenticate to reset parental control password"
            
            context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, error in
                if success {
                    // Clear the stored password data
                    self.userDefaults.removeObject(forKey: self.passwordHashKey)
                    self.userDefaults.removeObject(forKey: self.passwordSaltKey)
                    completion(true)
                } else {
                    if let error = error {
                        print("Authentication failed: \(error.localizedDescription)")
                    }
                    completion(false)
                }
            }
        } else {
            // Biometric authentication not available
            if let error = error {
                print("Biometric authentication not available: \(error.localizedDescription)")
            }
            completion(false)
        }
    }
    
    // MARK: - Private Helper Methods
    
    private func generateRandomSalt() -> String {
        var randomBytes = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, randomBytes.count, &randomBytes)
        return Data(randomBytes).base64EncodedString()
    }
    
    private func hashPassword(_ password: String, withSalt salt: String) -> String? {
        guard let passwordData = password.data(using: .utf8),
              let saltData = Data(base64Encoded: salt) else {
            return nil
        }
        
        // Combine password and salt
        let combinedData = passwordData + saltData
        
        // Hash using SHA-256
        let hashedData = SHA256.hash(data: combinedData)
        
        // Convert hash to string
        return hashedData.compactMap { String(format: "%02x", $0) }.joined()
    }
}
