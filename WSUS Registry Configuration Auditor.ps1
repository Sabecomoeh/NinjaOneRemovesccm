[CmdletBinding()] # Enables advanced cmdlet features like common parameters (e.g., -Verbose, -Debug)
param() # No parameters for this specific version of the script

# Enforce strict mode for better scripting practices.
# This helps catch common errors like using undeclared variables.
Set-StrictMode -Version Latest

#region Logging Configuration
# Define the directory where the log file will be saved.
# C:\temp is a common temporary directory, easy to find.
$logDirectory = "C:\temp"
# Create a unique log file name using the current date and time.
# This ensures each script run has its own log file, preventing overwrites.
$logFileName = "WSUS_Registry_Check_Log_$((Get-Date).ToString('yyyyMMdd_HHmmss')).log"
# Combine the directory and file name to get the full log file path.
$logFilePath = Join-Path -Path $logDirectory -ChildPath $logFileName

# Ensure the log directory exists. If it doesn't, create it.
# -Force allows creating the directory even if parent directories don't exist.
# -OutNull suppresses the output of New-Item, keeping the console clean.
if (-not (Test-Path $logDirectory -PathType Container)) {
    Write-Host "Log directory '$logDirectory' not found, creating it." -ForegroundColor Yellow
    New-Item -Path $logDirectory -ItemType Directory -Force | Out-Null
}

# Function to write messages to both the console and the log file.
# This centralizes logging, making it consistent and easy to manage.
function Write-Log {
    param (
        [string]$Message, # The message to log
        [string]$Level = "INFO" # The severity level of the message (INFO, WARNING, ERROR)
    )
    # Get the current timestamp for the log entry.
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    # Format the log entry string.
    $logEntry = "$timestamp [$Level] $Message"
    
    # Append the log entry to the log file.
    # Add-Content creates the file if it doesn't exist, like a digital diary.
    Add-Content -Path $logFilePath -Value $logEntry

    # Display the message on the console with appropriate coloring based on the log level.
    switch ($Level) {
        "INFO"    { Write-Host $Message -ForegroundColor Green }
        "WARNING" { Write-Host $Message -ForegroundColor Yellow }
        "ERROR"   { Write-Host $Message -ForegroundColor Red }
        Default   { Write-Host $Message } # Default color for unknown levels
    }
}
#endregion

#region Function: Test-Administrator
function Test-Administrator {
    # This helper function checks if the current PowerShell session is running with Administrator privileges.
    # It creates a WindowsPrincipal object for the current user and checks if they are in the Administrator role.
    # It returns $true if running as administrator, and $false otherwise.
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
#endregion

# --- Main script execution flow ---

Write-Log "--- Windows Update Registry Configuration Audit Script Started ---" -Level "INFO"
Write-Log "This script will audit your Windows Update client's registry settings, checking for lingering SCCM/WSUS configurations. Log file: $logFilePath" -Level "INFO"

# Step 1: Verify Administrator privileges. Script cannot proceed without them.
# It's like needing a Level 3 security clearance just to peek into the server logs.
if (-not (Test-Administrator)) {
    Write-Log "This script requires Administrator privileges to access system registry paths. Exiting." -Level "ERROR"
    Write-Host "Please right-click on the PowerShell script and select 'Run as administrator'. No admin, no audit. Them's the rules." -ForegroundColor Red
    exit 1 # Exit the script with an error code
}
Write-Log "Running with Administrator privileges. Access granted for the audit!" -Level "INFO"

# Define the primary registry paths for Windows Update policies.
# These are the digital breadcrumbs of past update management.
$wuRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$auRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"

# List of registry properties (values) to check in the WindowsUpdate path.
# These keys often point to WSUS servers or define specific SCCM-managed behaviors.
$wuPropertiesToCheck = @(
    "UpdateServiceUrlAlternate",
    "FillEmptyContentUrls",
    "TargetGroupEnabled",
    "TargetGroup",
    "ElevateNonAdmins",
    "WUServer",         # The primary suspect: WSUS server URL
    "WUStatusServer"    # The secondary suspect: WSUS status server URL
)

# List of registry properties (values) to check in the WindowsUpdate\AU path.
# These control Automatic Updates, some of which are influenced by WSUS.
# "NoAutoUpdate" and "AUOptions" are included here, as they were preserved in the removal script,
# so it's good to check their status too.
$auPropertiesToCheck = @(
    "UseWUServer",                 # The "are you still using WSUS?" question
    "DetectionFrequencyEnabled",
    "DetectionFrequency",
    "EnableFeaturedSoftware",
    "AutoInstallMinorUpdates",
    "IncludeRecommendedUpdates",
    "NoAutoUpdate", # This one was explicitly kept, good to know its value
    "AUOptions"     # This one was also explicitly kept, for update behavior
)

Write-Log "`nCommencing deep scan of WSUS-related registry settings. Prepare for revelation, or perhaps... anti-climax." -Level "INFO"

# --- Check registry properties in the WindowsUpdate path ---
Write-Log "`n--- Auditing Path: '$wuRegPath' ---" -Level "INFO"
if (Test-Path -Path $wuRegPath) {
    Write-Log "Registry path '$wuRegPath' found. Proceeding with sub-key inspection." -Level "INFO"
    foreach ($prop in $wuPropertiesToCheck) {
        try {
            # Attempt to retrieve the registry property.
            $value = Get-ItemProperty -LiteralPath $wuRegPath -Name $prop -ErrorAction SilentlyContinue
            if ($value -ne $null) {
                # If the property exists, log its presence and value.
                if ($value.$prop -is [int]) {
                    # For integer (dword) values, show both decimal and hexadecimal.
                    Write-Log "  '$prop': Present (Value: $($value.$prop) [dword:$(($value.$prop).ToString("X8"))])" -Level "INFO"
                } else {
                    # For other types, just show the string value.
                    Write-Log "  '$prop': Present (Value: '$($value.$prop)')" -Level "INFO"
                }
            } else {
                # If the property does not exist, log its absence.
                Write-Log "  '$prop': NOT Present. *Nada.* It seems this one has been decommissioned." -Level "INFO"
            }
        }
        catch {
            # Log any errors encountered while checking a specific property.
            Write-Log "  Failed to check registry property '$prop' in '$wuRegPath'. Error: $($_.Exception.Message)" -Level "ERROR"
        }
    }
} else {
    Write-Log "Registry path '$wuRegPath' does not exist. No signs of SCCM's presence here... or maybe it was just a ghost?" -Level "WARNING"
}

# --- Check registry properties in the WindowsUpdate\AU path ---
Write-Log "`n--- Auditing Path: '$auRegPath' ---" -Level "INFO"
if (Test-Path -Path $auRegPath) {
    Write-Log "Registry path '$auRegPath' found. Let's see what secrets it holds." -Level "INFO"
    foreach ($prop in $auPropertiesToCheck) {
        try {
            $value = Get-ItemProperty -LiteralPath $auRegPath -Name $prop -ErrorAction SilentlyContinue
            if ($value -ne $null) {
                if ($value.$prop -is [int]) {
                    Write-Log "  '$prop': Present (Value: $($value.$prop) [dword:$(($value.$prop).ToString("X8"))])" -Level "INFO"
                } else {
                    Write-Log "  '$prop': Present (Value: '$($value.$prop)')" -Level "INFO"
                }
            } else {
                Write-Log "  '$prop': NOT Present. Empty, like a server room after an EOL announcement." -Level "INFO"
            }
        }
        catch {
            Write-Log "  Failed to check registry property '$prop' in '$auRegPath'. Error: $($_.Exception.Message)" -Level "ERROR"
        }
    }
} else {
    Write-Log "Registry path '$auRegPath' does not exist. This system really wants to be free, doesn't it?" -Level "WARNING"
}

Write-Log "`n--- Registry Audit Finished ---" -Level "INFO"
Write-Host "Script completed. Your registry's secrets have been revealed! Check the log file at '$logFilePath' for the full report. Over and out, nerd patrol." -ForegroundColor Green
