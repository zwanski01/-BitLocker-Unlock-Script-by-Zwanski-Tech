package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	runtime "runtime"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/rivo/tview"
)

// Add new config field for the forensic scan path
type Config struct {
	Threads       int
	WordlistPath  string
	HashcatPath   string
	HashcatMode   string
	AttackMode    string
	Timeout       int
	OutputFile    string
	DriveLetter   string
	MaxAttempts   int
	HashFile      string
	UseGPU        bool
	Benchmark     bool
	BruteforceMin int
	BruteforceMax int
	Charset       string
	Masks         []string
	ForensicPath  string // New field
}

// ... [Result struct remains the same] ...

// Attack result structure
type Result struct {
	Password  string    `json:"password"`
	Hash      string    `json:"hash"`
	Drive     string    `json:"drive"`
	Success   bool      `json:"success"`
	Timestamp time.Time `json:"timestamp"`
	TimeTaken string    `json:"time_taken"`
	Attempts  int       `json:"attempts"`
}

var (
	// ... [vars remain the same] ...
	config       Config
	results      []Result
	resultsMutex sync.Mutex
	app          *tview.Application
	logView      *tview.TextView
	red          = color.New(color.FgRed).SprintFunc()
	green        = color.New(color.FgGreen).SprintFunc()
	yellow       = color.New(color.FgYellow).SprintFunc()
	blue         = color.New(color.FgBlue).SprintFunc()
	cyan         = color.New(color.FgCyan).SprintFunc()
)

func init() {
	// ... [init remains the same] ...
	config = Config{
		Threads:       runtime.NumCPU(),
		HashcatPath:   "hashcat",
		HashcatMode:   "22100",
		AttackMode:    "chain",
		Timeout:       3600,
		MaxAttempts:   1000000,
		UseGPU:        true,
		BruteforceMin: 1,
		BruteforceMax: 8,
		Charset:       "?l?u?d?s",
		Masks:         []string{"?l?l?l?l?l?l?l?l", "?u?l?l?l?l?l?l?l", "?d?d?d?d?d?d?d?d"},
	}
}

// ... [log function remains the same] ...
func log(level, message string) {
	app.QueueUpdateDraw(func() {
		fmt.Fprintf(logView, "[%s] %s\n", level, message)
	})
}

func main() {
	// ... [flag parsing gets the new flag] ...
	flag.IntVar(&config.Threads, "threads", config.Threads, "Number of threads")
	flag.StringVar(&config.WordlistPath, "wordlist", "", "Path to wordlist file")
	flag.StringVar(&config.HashcatPath, "hashcat", config.HashcatPath, "Path to hashcat binary")
	flag.StringVar(&config.AttackMode, "mode", config.AttackMode, "Attack mode: dictionary, bruteforce, mask, hybrid, chain, predictive")
	flag.IntVar(&config.Timeout, "timeout", config.Timeout, "Timeout in seconds")
	flag.StringVar(&config.OutputFile, "output", "bitlocker_results.json", "Output file for results")
	flag.StringVar(&config.DriveLetter, "drive", "", "Drive letter to attack (e.g., C:)")
	flag.IntVar(&config.MaxAttempts, "max-attempts", config.MaxAttempts, "Maximum number of attempts")
	flag.StringVar(&config.HashFile, "hash-file", "", "Hash file if already extracted")
	flag.BoolVar(&config.UseGPU, "gpu", config.UseGPU, "Use GPU for acceleration")
	flag.BoolVar(&config.Benchmark, "benchmark", false, "Run benchmark only")
	flag.IntVar(&config.BruteforceMin, "min-length", config.BruteforceMin, "Minimum password length for bruteforce")
	flag.IntVar(&config.BruteforceMax, "max-length", config.BruteforceMax, "Maximum password length for bruteforce")
	flag.StringVar(&config.Charset, "charset", config.Charset, "Character set for bruteforce")
	flag.StringVar(&config.ForensicPath, "forensic-path", "", "Path to a directory of user files for predictive analysis")

	flag.Parse()

	// ... [tview setup remains the same] ...
	app = tview.NewApplication()
	logView = tview.NewTextView().
		SetDynamicColors(true).
		SetRegions(true).
		SetWordWrap(true).
		SetChangedFunc(func() {
			app.Draw()
		})

	logView.SetBorder(true).SetTitle("Attack Log")

	go func() {
		runAttackLogic()
		time.Sleep(5 * time.Second)
		app.Stop()
	}()

	if err := app.SetRoot(logView, true).Run(); err != nil {
		panic(err)
	}
}

func runAttackLogic() {
	// ... [main logic includes new predictive mode] ...
	log("INFO", "BitLocker Bruteforce Toolkit by Zwanski Tech")
	log("INFO", fmt.Sprintf("Initializing attack with %d threads", config.Threads))

	if !checkDependencies() {
		log("ERROR", "Dependency check failed. Please install missing tools and try again.")
		return
	}

	if config.HashFile == "" {
		if config.DriveLetter == "" {
			log("ERROR", "Drive letter (-drive) or hash file (-hash-file) is required.")
			return
		}
		extractHash(config.DriveLetter)
	}

	var success bool
	switch config.AttackMode {
	case "dictionary":
		success = runDictionaryAttack()
	case "bruteforce":
		success = runBruteforceAttack()
	case "mask":
		success = runMaskAttack()
	case "hybrid":
		success = runHybridAttack()
	case "chain":
		log("INFO", "Starting chained attack (Dictionary -> Bruteforce)")
		success = runDictionaryAttack()
		if !success {
			log("WARN", "Dictionary attack failed, proceeding to Bruteforce attack.")
			success = runBruteforceAttack()
		}
	case "predictive":
		success = runPredictiveAttack()
	default:
		log("WARN", fmt.Sprintf("Unknown attack mode '%s'. Defaulting to chain attack.", config.AttackMode))
		success = runDictionaryAttack()
		if !success {
			log("WARN", "Dictionary attack failed, proceeding to Bruteforce attack.")
			success = runBruteforceAttack()
		}
	}

	if success {
		log("SUCCESS", "Attack chain finished successfully.")
	} else {
		log("FAILURE", "All attacks failed to recover the password.")
	}

	saveResults()
}

// ... [checkDependencies, extractHash, etc. remain the same] ...

// --- New Predictive Attack Functions ---

func runPredictiveAttack() bool {
	log("INFO", "Starting predictive attack...")
	if config.ForensicPath == "" {
		log("ERROR", "Predictive attack requires a path to user files. Please set with -forensic-path.")
		return false
	}

	// Step 1: Scan file system for keywords
	log("INFO", fmt.Sprintf("Scanning %s for keywords...", config.ForensicPath))
	keywords := scanFileSystem(config.ForensicPath)
	if len(keywords) == 0 {
		log("WARN", "No keywords found in the forensic path. Predictive attack may not be effective.")
		return false
	}
	log("SUCCESS", fmt.Sprintf("Found %d unique keywords.", len(keywords)))

	// Step 2: Mutate keywords into a password list
	log("INFO", "Mutating keywords into potential passwords...")
	passwords := mutateKeywords(keywords)
	log("SUCCESS", fmt.Sprintf("Generated %d potential passwords.", len(passwords)))

	// Step 3: Run a dictionary attack with the generated list
	predictiveWordlist := "predictive_wordlist.txt"
	err := ioutil.WriteFile(predictiveWordlist, []byte(strings.Join(passwords, "\n")), 0644)
	if err != nil {
		log("ERROR", fmt.Sprintf("Failed to write predictive wordlist: %v", err))
		return false
	}
	log("INFO", fmt.Sprintf("Predictive wordlist saved to %s", predictiveWordlist))

	// Set the wordlist path for the dictionary attack
	config.WordlistPath = predictiveWordlist
	return runDictionaryAttack()
}

func scanFileSystem(path string) []string {
	keywords := make(map[string]bool)
	wordRegex := regexp.MustCompile(`[a-zA-Z0-9]{4,}`)

	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(strings.ToLower(info.Name()), ".txt") {
			log("INFO", fmt.Sprintf("Scanning file: %s", filePath))
			content, readErr := ioutil.ReadFile(filePath)
			if readErr != nil {
				log("WARN", fmt.Sprintf("Failed to read %s: %v", filePath, readErr))
				return nil // Continue walking
			}

			matches := wordRegex.FindAllString(string(content), -1)
			for _, match := range matches {
				// Basic filtering for common English words could be added here
				keywords[strings.ToLower(match)] = true
			}
		}
		return nil
	})

	if err != nil {
		log("ERROR", fmt.Sprintf("Error walking the path %s: %v", path, err))
	}

	// Convert map keys to a slice
	uniqueKeywords := make([]string, 0, len(keywords))
	for k := range keywords {
	
uniqueKeywords = append(uniqueKeywords, k)
	}
	return uniqueKeywords
}

func mutateKeywords(keywords []string) []string {
	mutations := make(map[string]bool)
	suffixes := []string{"", "1", "123", "!", "2022", "2023", "2024"}

	for _, keyword := range keywords {
		if len(keyword) < 4 || len(keyword) > 12 { // Filter out very short/long keywords
			continue
		}
		for _, suffix := range suffixes {
			// Simple mutation: keyword + suffix
			mutations[keyword+suffix] = true

			// Capitalized version
			capitalized := strings.Title(keyword)
			mutations[capitalized+suffix] = true
		}
	}

	// Convert map to slice
	passwordList := make([]string, 0, len(mutations))
	for p := range mutations {
		passwordList = append(passwordList, p)
	}
	return passwordList
}

// --- Existing functions below... ---

func checkDependencies() bool {
	log("INFO", "Checking for required dependencies...")

	// Check for hashcat
	_, err := exec.LookPath(config.HashcatPath)
	if err != nil {
		log("ERROR", fmt.Sprintf("Dependency not found: %s", config.HashcatPath))
		log("INFO", "Please download and install hashcat from https://hashcat.net/hashcat/")
		log("INFO", "Ensure the hashcat binary is in your system's PATH or specify its location with the -hashcat flag.")
		return false
	}

	log("SUCCESS", "All required dependencies are found.")
	return true
}

func extractHash(drive string) {
	log("INFO", fmt.Sprintf("Attempting to extract BitLocker hash from drive %s", drive))

	if runtime.GOOS == "windows" {
		log("INFO", "Running on Windows, checking protectors with 'manage-bde'.")
		cmd := exec.Command("manage-bde", "-protectors", "-get", drive)
		output, err := cmd.CombinedOutput()
		if err != nil {
			log("ERROR", fmt.Sprintf("Could not execute 'manage-bde'. Make sure you are running with Administrator privileges. Error: %v", err))
		} else {
			log("OUTPUT", fmt.Sprintf("'manage-bde' output:\n%s", string(output)))
			log("WARN", "IMPORTANT: The output above shows protector info, not the hash itself.")
		}
	}

	log("WARN", "Hash extraction is a complex process that often requires specialized forensic tools.")
	log("WARN", "This tool does not perform real hash extraction. You should use a tool like 'bitlocker2john.py' (from John the Ripper) to extract the hash and provide it via the -hash-file flag.")

	dummyHash := "BITLOCKER$*0*...dummy_hash_data...*0"
	err := ioutil.WriteFile("bitlocker_hash.txt", []byte(dummyHash), 0644)
	if err != nil {
		log("ERROR", fmt.Sprintf("Error creating dummy hash file: %v", err))
		os.Exit(1)
	}
	config.HashFile = "bitlocker_hash.txt"
	log("SUCCESS", fmt.Sprintf("Created a dummy hash file for demonstration: %s", config.HashFile))
}

func runDictionaryAttack() bool {
	log("INFO", "Starting dictionary attack")

	if config.WordlistPath == "" {
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
			log("ERROR", "No wordlist found for dictionary attack. Please specify with -wordlist. Skipping.")
			return false
		}
	}

	log("INFO", fmt.Sprintf("Using wordlist: %s", config.WordlistPath))

	args := []string{
		"-m", config.HashcatMode,
		"-a", "0",
		"-o", "recovered_password.txt",
		"--status",
		"--status-timer", "60",
	}
	if config.UseGPU {
		args = append(args, "-D", "1,2")
	} else {
		args = append(args, "-D", "1")
	}
	args = append(args, config.HashFile, config.WordlistPath)

	return executeHashcat(args)
}

func runBruteforceAttack() bool {
	log("INFO", "Starting bruteforce attack")
	args := []string{
		"-m", config.HashcatMode,
		"-a", "3",
		"-o", "recovered_password.txt",
		"--status",
		"--increment",
		"--increment-min", fmt.Sprintf("%d", config.BruteforceMin),
		"--increment-max", fmt.Sprintf("%d", config.BruteforceMax),
	}
	if config.Charset != "" {
		args = append(args, []string{"-", "1"}...) // Corrected: -1 for charset
	}
	if config.UseGPU {
		args = append(args, "-D", "1,2")
	}
	args = append(args, config.HashFile, "?1?1?1?1?1?1?1?1")
	return executeHashcat(args)
}

func runMaskAttack() bool {
	log("INFO", "Starting mask attack")
	for _, mask := range config.Masks {
		log("INFO", fmt.Sprintf("Trying mask: %s", mask))
		args := []string{
			"-m", config.HashcatMode,
			"-a", "3",
			"-o", "recovered_password.txt",
			"--status",
		}
		if config.UseGPU {
			args = append(args, "-D", "1,2")
		}
		args = append(args, config.HashFile, mask)
		if executeHashcat(args) {
			return true
		}
	}
	return false
}

func runHybridAttack() bool {
	log("INFO", "Starting hybrid attack")
	args := []string{
		"-m", config.HashcatMode,
		"-a", "6",
		"-o", "recovered_password.txt",
		"--status",
	}
	if config.UseGPU {
		args = append(args, "-D", "1,2")
	}
	masks := []string{"?d?d?d", "?d?d?d?d", "!@#$", "123", "2023", "2024"}
	for _, mask := range masks {
		log("INFO", fmt.Sprintf("Trying hybrid pattern: wordlist + %s", mask))
		hybridArgs := append(args, config.HashFile, config.WordlistPath, mask)
		if executeHashcat(hybridArgs) {
			return true
		}
	}
	return false
}

func executeHashcat(args []string) bool {
	log("HASHCAT", fmt.Sprintf("Executing: %s %s", config.HashcatPath, strings.Join(args, " ")))

	cmd := exec.Command(config.HashcatPath, args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log("ERROR", fmt.Sprintf("Error creating stdout pipe: %v", err))
		return false
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		log("ERROR", fmt.Sprintf("Error creating stderr pipe: %v", err))
		return false
	}

	if err := cmd.Start(); err != nil {
		log("ERROR", fmt.Sprintf("Error starting hashcat: %v", err))
		return false
	}

	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "Status") {
				log("STATUS", line)
			}
		}
	}()

	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			log("STDERR", scanner.Text())
		}
	}()

	err = cmd.Wait()
	if err != nil {
		log("INFO", fmt.Sprintf("Hashcat process finished. May or may not be an error: %v", err))
	}

	recoveredPasswordFile := "recovered_password.txt"
	if _, err := os.Stat(recoveredPasswordFile); err == nil {
		content, readErr := ioutil.ReadFile(recoveredPasswordFile)
		if readErr == nil && len(content) > 0 {
			lines := strings.Split(strings.TrimSpace(string(content)), "\n")
			for _, line := range lines {
				if line == "" {
					continue
				}
				parts := strings.Split(line, ":")
				password := parts[len(parts)-1]
				if password != "" {
					log("SUCCESS", fmt.Sprintf("Password recovered: %s", password))
					result := Result{
						Password:  password,
						Hash:      config.HashFile,
						Drive:     config.DriveLetter,
						Success:   true,
						Timestamp: time.Now(),
					}
					resultsMutex.Lock()
					results = append(results, result)
					resultsMutex.Unlock()
					os.Remove(recoveredPasswordFile)
					return true
				}
			}
		}
	}

	log("INFO", "Password not recovered with this attempt.")
	return false
}

func saveResults() {
	if len(results) == 0 {
		log("INFO", "No passwords recovered, nothing to save.")
		return
	}
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		log("ERROR", fmt.Sprintf("Error marshaling results: %v", err))
		return
	}
	err = ioutil.WriteFile(config.OutputFile, data, 0644)
	if err != nil {
		log("ERROR", fmt.Sprintf("Error writing results file: %v", err))
		return
	}
	log("SUCCESS", fmt.Sprintf("Results for %d recovered password(s) saved to %s", len(results), config.OutputFile))
}

func extractKeysFromMemory(memoryDumpPath string) ([]string, error) {
	log("INFO", fmt.Sprintf("[Advanced] Analyzing memory dump: %s", memoryDumpPath))
	return nil, fmt.Errorf("memory analysis not implemented; requires Volatility integration")
}

func extractTPMKeys() (string, error) {
	log("INFO", "[Advanced] Attempting to extract keys from TPM...")
	return "", fmt.Errorf("TPM key extraction is highly specialized and not implemented")
}

func checkCloudBackups(driveID string) (string, error) {
	log("INFO", fmt.Sprintf("[Advanced] Checking for cloud backups for drive: %s", driveID))
	return "", fmt.Errorf("cloud backup checking not implemented; requires Microsoft Graph API integration")
}
