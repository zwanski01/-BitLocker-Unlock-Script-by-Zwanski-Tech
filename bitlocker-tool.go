package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/shirou/gopsutil/v3/disk"
)

// Configuration structure
type Config struct {
	Threads         int
	WordlistPath    string
	HashcatPath     string
	HashcatMode     string
	AttackMode      string
	Timeout         int
	OutputFile      string
	DriveLetter     string
	MaxAttempts     int
	HashFile        string
	UseGPU          bool
	Benchmark       bool
	DictionaryOnly  bool
	Bruteforce      bool
	BruteforceMin   int
	BruteforceMax   int
	Charset         string
	Masks           []string
}

// Attack result structure
type Result struct {
	Password    string    `json:"password"`
	Hash        string    `json:"hash"`
	Drive       string    `json:"drive"`
	Success     bool      `json:"success"`
	Timestamp   time.Time `json:"timestamp"`
	TimeTaken   string    `json:"time_taken"`
	Attempts    int       `json:"attempts"`
}

var (
	config       Config
	results      []Result
	resultsMutex sync.Mutex
	red          = color.New(color.FgRed).SprintFunc()
	green        = color.New(color.FgGreen).SprintFunc()
	yellow       = color.New(color.FgYellow).SprintFunc()
	blue         = color.New(color.FgBlue).SprintFunc()
	cyan         = color.New(color.FgCyan).SprintFunc()
	magenta      = color.New(color.FgMagenta).SprintFunc()
)

func init() {
	// Initialize default configuration
	config = Config{
		Threads:        runtime.NumCPU(),
		HashcatMode:    "22100", // BitLocker mode
		AttackMode:     "dictionary",
		Timeout:        3600,
		MaxAttempts:    1000000,
		UseGPU:         true,
		BruteforceMin:  1,
		BruteforceMax:  8,
		Charset:        "?l?u?d?s",
		Masks:          []string{"?l?l?l?l?l?l?l?l", "?u?l?l?l?l?l?l?l", "?d?d?d?d?d?d?d?d"},
	}
}

func main() {
	// Parse command line flags
	flag.IntVar(&config.Threads, "threads", config.Threads, "Number of threads")
	flag.StringVar(&config.WordlistPath, "wordlist", "", "Path to wordlist file")
	flag.StringVar(&config.HashcatPath, "hashcat", "hashcat", "Path to hashcat binary")
	flag.StringVar(&config.AttackMode, "mode", config.AttackMode, "Attack mode: dictionary, bruteforce, mask, hybrid")
	flag.IntVar(&config.Timeout, "timeout", config.Timeout, "Timeout in seconds")
	flag.StringVar(&config.OutputFile, "output", "bitlocker_results.json", "Output file for results")
	flag.StringVar(&config.DriveLetter, "drive", "", "Drive letter to attack (e.g., C:)")
	flag.IntVar(&config.MaxAttempts, "max-attempts", config.MaxAttempts, "Maximum number of attempts")
	flag.StringVar(&config.HashFile, "hash-file", "", "Hash file if already extracted")
	flag.BoolVar(&config.UseGPU, "gpu", config.UseGPU, "Use GPU for acceleration")
	flag.BoolVar(&config.Benchmark, "benchmark", false, "Run benchmark only")
	flag.BoolVar(&config.DictionaryOnly, "dictionary", false, "Use dictionary attack only")
	flag.BoolVar(&config.Bruteforce, "bruteforce", false, "Enable bruteforce attack")
	flag.IntVar(&config.BruteforceMin, "min-length", config.BruteforceMin, "Minimum password length for bruteforce")
	flag.IntVar(&config.BruteforceMax, "max-length", config.BruteforceMax, "Maximum password length for bruteforce")
	flag.StringVar(&config.Charset, "charset", config.Charset, "Character set for bruteforce")

	flag.Parse()

	fmt.Printf("%s BitLocker Bruteforce Toolkit by Zwanski Tech\n", blue("[INFO]"))
	fmt.Printf("%s Initializing attack with %d threads\n", blue("[INFO]"), config.Threads)

	// Check if hashcat is available
	if !checkHashcat() {
		fmt.Printf("%s Hashcat not found. Please install hashcat and ensure it's in your PATH.\n", red("[ERROR]"))
		os.Exit(1)
	}

	// Extract BitLocker hash if not provided
	if config.HashFile == "" {
		if config.DriveLetter == "" {
			fmt.Printf("%s Drive letter (-drive) or hash file (-hash-file) is required.\n", red("[ERROR]"))
			os.Exit(1)
		}
		extractHash(config.DriveLetter)
	}

	// Run selected attack mode
	switch config.AttackMode {
	case "dictionary":
		runDictionaryAttack()
	case "bruteforce":
		runBruteforceAttack()
	case "mask":
		runMaskAttack()
	case "hybrid":
		runHybridAttack()
	default:
		runDictionaryAttack()
	}

	// Save results
	saveResults()
}

func checkHashcat() bool {
	cmd := exec.Command(config.HashcatPath, "--version")
	err := cmd.Run()
	return err == nil
}

func extractHash(drive string) {
	fmt.Printf("%s Attempting to extract BitLocker hash from drive %s\n", blue("[INFO]"), drive)

	if runtime.GOOS == "windows" {
		fmt.Printf("%s Running on Windows, checking protectors with 'manage-bde'.\n", blue("[INFO]"))
		cmd := exec.Command("manage-bde", "-protectors", "-get", drive)
		output, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("%s Could not execute 'manage-bde'. Make sure you are running with Administrator privileges. Error: %v\n", red("[ERROR]"), err)
			fmt.Printf("%s Output: %s\n", red("[STDERR]"), string(output))
		} else {
			fmt.Printf("%s 'manage-bde' output:\n%s\n", cyan("[OUTPUT]"), string(output))
			fmt.Printf("%s IMPORTANT: The output above shows protector info, not the hash itself.\n", yellow("[WARN]"))
		}
	}

	fmt.Printf("%s Hash extraction is a complex process that often requires specialized forensic tools.\n", yellow("[WARN]"))
	fmt.Printf("%s This tool does not perform real hash extraction. You should use a tool like 'bitlocker2john.py' (from John the Ripper) to extract the hash and provide it via the -hash-file flag.\n", yellow("[WARN]"))

	// For demonstration, we'll create a dummy hash file
	dummyHash := "BITLOCKER$*0*...dummy_hash_data...*0" // A more realistic-looking dummy hash
	err := ioutil.WriteFile("bitlocker_hash.txt", []byte(dummyHash), 0644)
	if err != nil {
		fmt.Printf("%s Error creating dummy hash file: %v\n", red("[ERROR]"), err)
		os.Exit(1)
	}
	config.HashFile = "bitlocker_hash.txt"
	fmt.Printf("%s Created a dummy hash file for demonstration: %s\n", green("[SUCCESS]"), config.HashFile)
}


func runDictionaryAttack() {
	fmt.Printf("%s Starting dictionary attack\n", blue("[INFO]"))

	if config.WordlistPath == "" {
		// Use default wordlists
		defaultWordlists := []string{
			"/usr/share/wordlists/rockyou.txt",
			"/usr/share/wordlists/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt",
			"./wordlists/common_passwords.txt",
		}

		for _, wordlist := range defaultWordlists {
			if _, err := os.Stat(wordlist); err == nil {
				config.WordlistPath = wordlist
				break
			}
		}

		if config.WordlistPath == "" {
			fmt.Printf("%s No wordlist found. Please specify with -wordlist\n", red("[ERROR]"))
			os.Exit(1)
		}
	}

	fmt.Printf("%s Using wordlist: %s\n", blue("[INFO]"), config.WordlistPath)

	// Build hashcat command
	args := []string{
		"-m", config.HashcatMode,
		"-a", "0", // Dictionary attack
		"-o", "recovered_password.txt",
		"--status",
		"--status-timer", "60",
	}

	if config.UseGPU {
		args = append(args, "-D", "1,2") // Use GPU
	} else {
		args = append(args, "-D", "1") // Use CPU only
	}

	args = append(args, config.HashFile, config.WordlistPath)

	// Execute hashcat
	executeHashcat(args)
}

func runBruteforceAttack() {
	fmt.Printf("%s Starting bruteforce attack\n", blue("[INFO]"))

	args := []string{
		"-m", config.HashcatMode,
		"-a", "3", // Bruteforce attack
		"-o", "recovered_password.txt",
		"--status",
		"--increment",
		"--increment-min", fmt.Sprintf("%d", config.BruteforceMin),
		"--increment-max", fmt.Sprintf("%d", config.BruteforceMax),
	}

	if config.Charset != "" {
		args = append(args, []string{"-1", config.Charset}...)
	}

	if config.UseGPU {
		args = append(args, "-D", "1,2")
	}

	args = append(args, config.HashFile, "?1?1?1?1?1?1?1?1")

	executeHashcat(args)
}

func runMaskAttack() {
	fmt.Printf("%s Starting mask attack\n", blue("[INFO]"))

	for _, mask := range config.Masks {
		fmt.Printf("%s Trying mask: %s\n", blue("[INFO]"), mask)

		args := []string{
			"-m", config.HashcatMode,
			"-a", "3", // Mask attack
			"-o", "recovered_password.txt",
			"--status",
		}

		if config.UseGPU {
			args = append(args, "-D", "1,2")
		}

		args = append(args, config.HashFile, mask)

		if executeHashcat(args) {
			break // Stop if password found
		}
	}
}

func runHybridAttack() {
	fmt.Printf("%s Starting hybrid attack\n", blue("[INFO]"))

	// Hybrid attack: dictionary + masks
	args := []string{
		"-m", config.HashcatMode,
		"-a", "6", // Hybrid attack (dict + mask)
		"-o", "recovered_password.txt",
		"--status",
	}

	if config.UseGPU {
		args = append(args, "-D", "1,2")
	}

	// Use common masks for hybrid attack
	masks := []string{"?d?d?d", "?d?d?d?d", "!@#$", "123", "2023", "2024"}

	for _, mask := range masks {
		fmt.Printf("%s Trying hybrid pattern: wordlist + %s\n", blue("[INFO]"), mask)

		hybridArgs := append(args, config.HashFile, config.WordlistPath, mask)

		if executeHashcat(hybridArgs) {
			break
		}
	}
}

func executeHashcat(args []string) bool {
	fmt.Printf("%s Executing: %s %s\n", cyan("[HASHCAT]"), config.HashcatPath, strings.Join(args, " "))

	cmd := exec.Command(config.HashcatPath, args...)

	// Capture output
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Printf("%s Error creating stdout pipe: %v\n", red("[ERROR]"), err)
		return false
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		fmt.Printf("%s Error creating stderr pipe: %v\n", red("[ERROR]"), err)
		return false
	}

	// Start command
	if err := cmd.Start(); err != nil {
		fmt.Printf("%s Error starting hashcat: %v\n", red("[ERROR]"), err)
		return false
	}

	// Read output in real-time
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "Status") {
				fmt.Printf("%s %s\n", yellow("[STATUS]"), line)
			}
		}
	}()

	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			fmt.Printf("%s %s\n", red("[STDERR]"), line)
		}
	}()

	// Wait for completion
	err = cmd.Wait()
	if err != nil {
		fmt.Printf("%s Hashcat completed with error: %v\n", red("[ERROR]"), err)
	}

	// Check if password was recovered
	recoveredPasswordFile := "recovered_password.txt"
	if _, err := os.Stat(recoveredPasswordFile); err == nil {
		content, readErr := ioutil.ReadFile(recoveredPasswordFile)
		if readErr == nil && len(content) > 0 {
			// The file can contain more than just the password, need to parse it.
			// Format is often: hash:password
			lines := strings.Split(strings.TrimSpace(string(content)), "\n")
			for _, line := range lines {
				parts := strings.Split(line, ":")
				password := parts[len(parts)-1] // The password is the last part

				if password != "" {
					fmt.Printf("%s Password recovered: %s\n", green("[SUCCESS]"), password)

					result := Result{
						Password:  password,
						Hash:      config.HashFile,
						Drive:     config.DriveLetter,
						Success:   true,
						Timestamp: time.Now(),
						// TimeTaken and Attempts would require more complex parsing of hashcat output
					}

					resultsMutex.Lock()
					results = append(results, result)
					resultsMutex.Unlock()

					// Clean up the recovery file for the next run
				os.Remove(recoveredPasswordFile)
					return true
				}
			}
		}
	}

	fmt.Printf("%s Password not recovered with this attempt.\n", red("[INFO]"))
	return false
}

func saveResults() {
	if len(results) == 0 {
		fmt.Printf("%s No passwords recovered, nothing to save.\n", blue("[INFO]"))
		return
	}
	// Save results to JSON file
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Printf("%s Error marshaling results: %v\n", red("[ERROR]"), err)
		return
	}

	err = ioutil.WriteFile(config.OutputFile, data, 0644)
	if err != nil {
		fmt.Printf("%s Error writing results file: %v\n", red("[ERROR]"), err)
		return
	}

	fmt.Printf("%s Results for %d recovered password(s) saved to %s\n", green("[SUCCESS]"), len(results), config.OutputFile)
}

// --- Advanced Feature Stubs ---
// The following functions are placeholders to illustrate where advanced functionality could be integrated.

// extractKeysFromMemory demonstrates integration with a memory analysis tool like Volatility.
func extractKeysFromMemory(memoryDumpPath string) ([]string, error) {
	fmt.Printf("%s [Advanced] Analyzing memory dump: %s\n", blue("[INFO]"), memoryDumpPath)

	// PREREQUISITE: Volatility 3 framework must be installed and configured.
	// The command might look something like this:
	// `python3 vol.py -f <memory_dump> windows.bitlocker.keys`

	// This is a placeholder. A real implementation would:
	// 1. Verify Volatility is installed.
	// 2. Execute the appropriate Volatility command as a subprocess.
	// 3. Parse the output to extract potential keys.
	// 4. Return the found keys.

	return nil, fmt.Errorf("memory analysis not implemented; requires Volatility integration")
}

// extractTPMKeys demonstrates the concept of TPM key extraction.
func extractTPMKeys() (string, error) {
	fmt.Printf("%s [Advanced] Attempting to extract keys from TPM...\n", blue("[INFO]"))

	// WARNING: Interacting with a TPM is highly complex, platform-specific, and risky.
	// It often requires specialized hardware and software (e.g., a TPM sniffer) or exploiting vulnerabilities.

	// This is a placeholder. A real implementation is beyond the scope of a simple script
	// and would involve low-level hardware interaction.

	return "", fmt.Errorf("TPM key extraction is highly specialized and not implemented")
}

// checkCloudBackups demonstrates checking for cloud-backed-up recovery keys.
func checkCloudBackups(driveID string) (string, error) {
	fmt.Printf("%s [Advanced] Checking for cloud backups for drive: %s\n", blue("[INFO]"), driveID)

	// PREREQUISITE: This would require authentication with a Microsoft Account or Azure AD.
	// It would likely involve using the Microsoft Graph API.

	// This is a placeholder. A real implementation would:
	// 1. Implement an OAuth2 flow to get an access token for the Microsoft Graph API.
	// 2. Make API calls to the relevant endpoints (e.g., /me/drive/special/cameraroll) to find BitLocker recovery keys.
	// 3. Handle permissions and consent.

	return "", fmt.Errorf("cloud backup checking not implemented; requires Microsoft Graph API integration")
}
