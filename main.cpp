# ElevenValueBoolean

**Author:** Cadell Richard Anderson  
**License:** Custom License: ElevenValueBoolean Attribution License (EAL) v1.0
**Version:** 0.2  
**Date:** July 2025
    
#define NOMINMAX
#include <windows.h>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <unordered_map>
#include <vector>
#include <cmath>
#include <iomanip>
#include <string>
#include <filesystem>
#include <locale>
#include <codecvt> // Still needed for the deprecated std::wstring_convert or for other locale related things. We will replace its specific use.

// Constants
constexpr size_t BLOCK_SIZE = 4096;

// Calculate Shannon entropy
double calculateEntropy(const std::vector<unsigned char>& data) {
    std::unordered_map<unsigned char, size_t> freq;
    for (unsigned char byte : data) freq[byte]++;

    double entropy = 0.0;
    for (const auto& pair : freq) {
        double p = static_cast<double>(pair.second) / data.size();
        entropy -= p * std::log2(p);
    }
    return entropy;
}

/**
 * @brief The ElevenValueBoolean class represents a boolean concept with eleven distinct states (0-10).
 *
 * This class extends the traditional boolean logic to an undecimal (base-11) system,
 * where each state carries a nuanced meaning from "absolute uncertainty" to "absolute certainty/contradiction."
 * It incorporates "undenary dynamics using chaos theory" by applying a non-linear transformation
 * to the results of logical operations, making the state transitions more complex and less
 * directly predictable than standard boolean algebra.
 */
class ElevenValueBoolean {
public:
    // Enum for the eleven logical states, directly mapping to values 0-10.
    // Each state is represented by an unsigned char to ensure a compact memory footprint.
    enum State : unsigned char {
        AbsoluteUncertainty = 0,  // 0 - Complete lack of information, akin to 'Neither' but more profound.
        HighlyUnlikely = 1,  // 1 - Very weak falsehood, almost certainly not true.
        Unlikely = 2,  // 2 - Weak falsehood.
        SomewhatFalse = 3,  // 3 - Leaning towards false.
        ModeratelyFalse = 4,  // 4 - Clearly false, but not absolutely.
        Neutral = 5,  // 5 - Midpoint, truly undetermined, balanced.
        ModeratelyTrue = 6,  // 6 - Clearly true, but not absolutely.
        SomewhatTrue = 7,  // 7 - Leaning towards true.
        Likely = 8,  // 8 - Weak truth.
        HighlyLikely = 9,  // 9 - Very strong truth, almost certainly true.
        AbsoluteCertainty = 10  // 10 - Absolute truth or absolute contradiction (maximal information/conflict), akin to 'Both'.
    };

private:
    State current_state; // The private member variable holding the current state of the boolean.

    // A simple pseudo-chaotic function. This function introduces non-linearity.
    // It's a simplified logistic map-like transformation, scaled to the 0-10 range.
    // The 'r' parameter (rate) influences the "chaotic" behavior.
    // For values of 'r' > 4, the logistic map exhibits chaotic behavior.
    // Here, we use a fixed 'r' and scale the output to fit our 0-10 state range.
    // This function is deterministic but non-linear, mimicking a chaotic influence.
    double applyChaoticInfluence(double value) const {
        const double r = 3.9; // A parameter for the logistic map, chosen for chaotic-like behavior.
        // Normalize value to [0, 1] range for logistic map application.
        double normalized_value = value / 10.0;
        // Apply logistic map formula.
        double transformed_value = r * normalized_value * (1.0 - normalized_value);
        // Scale back to [0, 10] and round to the nearest integer state.
        return std::round(transformed_value * 10.0);
    }

    // Helper to clamp a double value to the valid State range [0, 10].
    State clampState(double value) const {
        if (value < 0.0) return static_cast<State>(0);
        if (value > 10.0) return static_cast<State>(10);
        return static_cast<State>(static_cast<unsigned char>(std::round(value)));
    }

public:
    // Default Constructor: Initializes the boolean to AbsoluteUncertainty (0).
    // This provides a neutral starting point when no specific value is provided.
    ElevenValueBoolean() : current_state(AbsoluteUncertainty) {
        // std::cout << "ElevenValueBoolean created: Initialized to AbsoluteUncertainty (0)." << std::endl;
    }

    // Constructor with State parameter: Initializes the boolean with a specific State.
    // Allows direct assignment of one of the defined eleven states.
    ElevenValueBoolean(State initial_state) : current_state(initial_state) {
        // std::cout << "ElevenValueBoolean created: Initialized to state " << static_cast<int>(initial_state) << "." << std::endl;
    }

    // Constructor with integer parameter: Initializes the boolean with an integer value (0-10).
    // This provides flexibility for setting the state using numerical inputs.
    // Input is clamped to ensure it falls within the valid State range [0, 10].
    ElevenValueBoolean(int initial_value) : current_state(clampState(static_cast<double>(initial_value))) {
        // std::cout << "ElevenValueBoolean created: Initialized with integer value " << initial_value
        //           << ", clamped to state " << static_cast<int>(current_state) << "." << std::endl;
    }

    // Destructor: Cleans up resources. For this simple class, it's trivial (no dynamic memory).
    // Included for completeness and to demonstrate proper class structure.
    ~ElevenValueBoolean() {
        // std::cout << "ElevenValueBoolean destroyed: State " << static_cast<int>(current_state) << "." << std::endl;
    }

    // Getter for the current state.
    // Allows external access to the internal state of the boolean.
    State getState() const {
        return current_state;
    }

    // Setter for the current state.
    // Allows modification of the internal state. Input is clamped.
    void setState(State new_state) {
        current_state = new_state;
    }

    // Setter with integer parameter, clamps the input.
    void setState(int new_value) {
        current_state = clampState(static_cast<double>(new_value));
    }

    // Operator Overloads for Logical Operations:

    // Logical NOT (!) operator.
    // Inverts the "truthiness" of the state.
    // States closer to 0 become closer to 10, and vice-versa.
    // A chaotic influence is applied to the result.
    ElevenValueBoolean operator!() const {
        // Simple inversion: 10 - current_state.
        // Example: NOT(0) -> 10, NOT(5) -> 5, NOT(10) -> 0.
        double inverted_value = 10.0 - static_cast<double>(current_state);
        double influenced_value = applyChaoticInfluence(inverted_value);
        return ElevenValueBoolean(clampState(influenced_value));
    }

    // Logical AND (&&) operator.
    // Combines two ElevenValueBoolean instances.
    // The result leans towards the "falser" or lower state, but with chaotic influence.
    ElevenValueBoolean operator&&(const ElevenValueBoolean& other) const {
        // For AND, the result tends towards the minimum (falser) value.
        // We take a weighted average or a combination that favors the lower value.
        // A simple approach is the average, then apply influence.
        double combined_value = (static_cast<double>(current_state) + static_cast<double>(other.current_state)) / 2.0;
        // Introduce a bias towards the minimum for AND-like behavior.
        combined_value = std::min(combined_value, static_cast<double>(std::min(current_state, other.current_state) + 2)); // Bias towards lower
        double influenced_value = applyChaoticInfluence(combined_value);
        return ElevenValueBoolean(clampState(influenced_value));
    }

    // Logical OR (||) operator.
    // Combines two ElevenValueBoolean instances.
    // The result leans towards the "truer" or higher state, but with chaotic influence.
    ElevenValueBoolean operator||(const ElevenValueBoolean& other) const {
        // For OR, the result tends towards the maximum (truer) value.
        // A simple approach is the average, then apply influence.
        double combined_value = (static_cast<double>(current_state) + static_cast<double>(other.current_state)) / 2.0;
        // Introduce a bias towards the maximum for OR-like behavior.
        combined_value = std::max(combined_value, static_cast<double>(std::max(current_state, other.current_state) - 2)); // Bias towards higher
        double influenced_value = applyChaoticInfluence(combined_value);
        return ElevenValueBoolean(clampState(influenced_value));
    }

    // State Checkers:
    // These methods provide a way to interpret the eleven states into more traditional boolean concepts.
    // The definitions are subjective and based on the chosen semantics of the 11 states.

    // Checks if the state is considered "True" (ModeratelyTrue or higher).
    bool isTrue() const {
        return current_state >= ModeratelyTrue;
    }

    // Checks if the state is considered "False" (ModeratelyFalse or lower).
    bool isFalse() const {
        return current_state <= ModeratelyFalse;
    }

    // Checks if the state is considered "Neither" (AbsoluteUncertainty or Neutral).
    bool isNeither() const {
        return current_state == AbsoluteUncertainty || current_state == Neutral;
    }

    // Checks if the state is considered "Both" (AbsoluteCertainty, implying contradiction or maximal information).
    bool isBoth() const {
        return current_state == AbsoluteCertainty;
    }

    // Checks if the state is considered "Likely" (Likely or HighlyLikely).
    bool isLikely() const {
        return current_state >= Likely;
    }

    // Checks if the state is considered "HighlyLikely" (HighlyLikely).
    bool isHighlyLikely() const {
        return current_state == HighlyLikely;
    }

    // Provides a string description for the current state.
    // Useful for debugging and understanding the state.
    std::string toString() const {
        switch (current_state) {
        case AbsoluteUncertainty: return "AbsoluteUncertainty (0)";
        case HighlyUnlikely:      return "HighlyUnlikely (1)";
        case Unlikely:            return "Unlikely (2)";
        case SomewhatFalse:       return "SomewhatFalse (3)";
        case ModeratelyFalse:     return "ModeratelyFalse (4)";
        case Neutral:             return "Neutral (5)";
        case ModeratelyTrue:      return "ModeratelyTrue (6)";
        case SomewhatTrue:        return "SomewhatTrue (7)";
        case Likely:              return "Likely (8)";
        case HighlyLikely:        return "HighlyLikely (9)";
        case AbsoluteCertainty:   return "AbsoluteCertainty (10)";
        default:                  return "Unknown State"; // Should not happen with clamped values
        }
    }
};

// Overload operator<< for std::ostream (for std::cout)
std::ostream& operator<<(std::ostream& os, ElevenValueBoolean val) {
    return os << val.toString();
}

// Helper function to convert std::string to std::wstring using Windows API
std::wstring StringToWString(const std::string& s) {
    int len;
    // +1 for null terminator for MultiByteToWideChar
    int slength = (int)s.length() + 1;
    len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), slength, 0, 0);
    std::wstring buf(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), slength, &buf[0], len);
    return buf;
}

// Overload operator<< for std::wostream (for std::wcout)
std::wostream& operator<<(std::wostream& os, ElevenValueBoolean val) {
    // Convert std::string from ElevenValueBooleanToString to std::wstring using Windows API
    std::string s = val.toString();
    return os << StringToWString(s);
}

// Enhanced analyzeFileEntropy to return ElevenValueBoolean
ElevenValueBoolean analyzeFileEntropy(const std::wstring& filePath) {
    FILE* fp = nullptr;
    errno_t err = _wfopen_s(&fp, filePath.c_str(), L"rb");
    if (err != 0 || !fp) {
        std::wcerr << L"[-] Cannot open: " << filePath << L"\n";
        return ElevenValueBoolean(ElevenValueBoolean::State::AbsoluteUncertainty); // Cannot open file, so no information
    }

    std::wcout << L"\n=== Entropy Analysis: " << filePath << L" ===\n";

    size_t blockIndex = 0;
    double totalEntropy = 0.0, minEntropy = 9.0, maxEntropy = 0.0;
    size_t blockCount = 0;

    std::vector<unsigned char> buffer(BLOCK_SIZE);
    while (true) {
        size_t bytesRead = fread(buffer.data(), 1, BLOCK_SIZE, fp);
        if (bytesRead == 0) break;

        buffer.resize(bytesRead);
        double entropy = calculateEntropy(buffer);
        totalEntropy += entropy;
        minEntropy = std::min(minEntropy, entropy);
        maxEntropy = std::max(maxEntropy, entropy);

        std::wcout << L"Block " << std::setw(4) << blockIndex++ << L" | Entropy: "
            << std::fixed << std::setprecision(4) << entropy << L" | ";

        // Mapping entropy to a visual indicator
        if (entropy < 5.0) std::wcout << L"[VERY LOW]   ";
        else if (entropy < 7.0) std::wcout << L"[NORMAL]     ";
        else if (entropy < 8.5) std::wcout << L"[SUSPICIOUS] ";
        else std::wcout << L"[CRITICAL!]  ";

        for (int i = 0; i < static_cast<int>(entropy * 2); ++i)
            std::wcout << L"|";
        std::wcout << L"\n";

        buffer.resize(BLOCK_SIZE);
        blockCount++;
    }

    fclose(fp);

    if (blockCount == 0) {
        std::wcerr << L"[-] No data read from file.\n";
        return ElevenValueBoolean(ElevenValueBoolean::State::AbsoluteUncertainty); // No data, no information
    }

    double avgEntropy = totalEntropy / blockCount;

    std::wcout << L"\n[Summary]\n";
    std::wcout << L"  Total Blocks:    " << blockCount << L"\n";
    std::wcout << L"  Average Entropy: " << std::fixed << std::setprecision(4) << avgEntropy << L"\n";
    std::wcout << L"  Min Entropy:     " << minEntropy << L"\n";
    std::wcout << L"  Max Entropy:     " << maxEntropy << L"\n";

    // Determine the ElevenValueBoolean result based on entropy
    if (avgEntropy >= 9.8 || maxEntropy >= 9.8) {
        std::wcout << L"[!] ABSOLUTE CERTAINTY OF HIGH ENTROPY. -> AbsoluteCertainty (Malicious)\n";
        return ElevenValueBoolean(ElevenValueBoolean::State::AbsoluteCertainty);
    }
    else if (avgEntropy >= 9.5 || maxEntropy >= 9.5) {
        std::wcout << L"[!] HIGHLY LIKELY HIGH ENTROPY. -> HighlyLikely (Malicious)\n";
        return ElevenValueBoolean(ElevenValueBoolean::State::HighlyLikely);
    }
    else if (avgEntropy >= 9.0 || maxEntropy >= 9.0) {
        std::wcout << L"[!] LIKELY HIGH ENTROPY. -> Likely (Malicious)\n";
        return ElevenValueBoolean(ElevenValueBoolean::State::Likely);
    }
    else if (avgEntropy >= 8.5 || maxEntropy >= 8.5) {
        std::wcout << L"[!] SOMEWHAT TRUE (Elevated Entropy). -> SomewhatTrue\n";
        return ElevenValueBoolean(ElevenValueBoolean::State::SomewhatTrue);
    }
    else if (avgEntropy >= 8.0 || maxEntropy >= 8.0) {
        std::wcout << L"[!] MODERATELY TRUE (Suspicious Entropy). -> ModeratelyTrue\n";
        return ElevenValueBoolean(ElevenValueBoolean::State::ModeratelyTrue);
    }
    else if (avgEntropy >= 7.5 || maxEntropy >= 7.5) {
        std::wcout << L"[!] NEUTRAL (Indeterminate Entropy). -> Neutral\n";
        return ElevenValueBoolean(ElevenValueBoolean::State::Neutral);
    }
    else if (avgEntropy >= 7.0 || maxEntropy >= 7.0) {
        std::wcout << L"[!] MODERATELY FALSE (Slightly Elevated but Benign). -> ModeratelyFalse\n";
        return ElevenValueBoolean(ElevenValueBoolean::State::ModeratelyFalse);
    }
    else if (avgEntropy >= 6.5 || maxEntropy >= 6.5) {
        std::wcout << L"[!] SOMEWHAT FALSE (Normal Entropy). -> SomewhatFalse\n";
        return ElevenValueBoolean(ElevenValueBoolean::State::SomewhatFalse);
    }
    else if (avgEntropy >= 6.0 || maxEntropy >= 6.0) {
        std::wcout << L"[!] UNLIKELY (Low Entropy). -> Unlikely\n";
        return ElevenValueBoolean(ElevenValueBoolean::State::Unlikely);
    }
    else if (avgEntropy >= 5.0 || maxEntropy >= 5.0) {
        std::wcout << L"[!] HIGHLY UNLIKELY (Very Low Entropy). -> HighlyUnlikely\n";
        return ElevenValueBoolean(ElevenValueBoolean::State::HighlyUnlikely);
    }
    else {
        std::wcout << L"[!] ABSOLUTE UNCERTAINTY (Extremely Low Entropy). -> AbsoluteUncertainty\n";
        return ElevenValueBoolean(ElevenValueBoolean::State::AbsoluteUncertainty);
    }
}

// New helper function to copy files
bool copyFileToFolder(const std::wstring& sourcePath, const std::wstring& destFolderPath) {
    // Ensure the destination directory exists
    if (!std::filesystem::exists(destFolderPath)) {
        std::error_code ec;
        if (!std::filesystem::create_directories(destFolderPath, ec)) {
            std::wcerr << L"[-] Failed to create destination directory '" << destFolderPath << L"': " << ec.message().c_str() << L"\n";
            return false;
        }
    }

    std::filesystem::path source_fs_path(sourcePath);
    std::filesystem::path dest_fs_path(destFolderPath);
    dest_fs_path /= source_fs_path.filename(); // Append source file name to destination path

    std::wcout << L"[i] Attempting to copy from:\n    " << sourcePath << L"\n    to:\n    " << dest_fs_path.c_str() << L"\n";

    // Copy the file. FALSE means it will fail if the file already exists.
    if (CopyFileW(sourcePath.c_str(), dest_fs_path.c_str(), FALSE)) {
        return true;
    }
    else {
        DWORD error = GetLastError();
        std::wcerr << L"[-] CopyFileW failed with error code: " << error << L". (Source: " << sourcePath << L", Dest: " << dest_fs_path.c_str() << L")\n";
        // Specific handling for ERROR_FILE_EXISTS
        if (error == ERROR_FILE_EXISTS) {
            std::wcerr << L"    File already exists in the destination folder.\n";
        }
        return false;
    }
}


int main() {
    SetConsoleOutputCP(CP_UTF8);
    std::ios::sync_with_stdio(false);

    wchar_t systemDrive[MAX_PATH] = { 0 };
    DWORD len = GetEnvironmentVariableW(L"SystemDrive", systemDrive, MAX_PATH);
    if (len == 0 || len > MAX_PATH) {
        std::wcerr << L"[-] Failed to detect system drive.\n";
        return 1;
    }

    std::wstring root = std::wstring(systemDrive) + L"\\";
    // Define the destination folder for suspicious/critical files
    // IMPORTANT: Ensure this folder exists or the program has permissions to create it.
    // For testing, you might want to create C:\SuspiciousFiles manually or change this path.
    const std::wstring destinationFolder = L"C:\\Users\\Noob\\OneDrive\\Desktop\\Desktop\\ScanSuspisciousResults\\bigscan3";

    std::wcout << L"[+] Scanning all files on system drive: " << root << L"\n";

    try {
        std::unordered_map<std::wstring, ElevenValueBoolean> file_suspiciousness;

        for (const auto& entry : std::filesystem::recursive_directory_iterator(
            root, std::filesystem::directory_options::skip_permission_denied)) {

            if (entry.is_regular_file()) {
                ElevenValueBoolean file_status = analyzeFileEntropy(entry.path().wstring());
                file_suspiciousness[entry.path().wstring()] = file_status;
                std::wcout << L"Overall Entropy Status for " << entry.path().wstring() << L": " << file_status << L"\n";

                // Logic to copy suspicious or critical files based on ElevenValueBoolean states
                // Files are considered "alertive" if they are ModeratelyTrue or higher, or AbsoluteCertainty.
                if (file_status.isTrue() || file_status.isBoth() || file_status.isLikely() || file_status.isHighlyLikely()) {
                    std::wcout << L"[!] Alertive entropy detected. Attempting to copy file to quarantine folder...\n";
                    if (copyFileToFolder(entry.path().wstring(), destinationFolder)) {
                        std::wcout << L"[+] File copied successfully to: " << destinationFolder << L"\n";
                    }
                    else {
                        // Error message handled inside copyFileToFolder
                    }
                }
            }
        }

        std::wcout << L"\n--- Summary of File Entropy Statuses ---\n";
        for (const auto& pair : file_suspiciousness) {
            std::wcout << L"File: " << pair.first << L" | Status: " << pair.second << L"\n";
        }

    }
    catch (const std::exception& e) {
        std::cerr << "[!] Exception while scanning: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
