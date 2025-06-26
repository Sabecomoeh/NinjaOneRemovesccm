[CmdletBinding()] # Enables advanced cmdlet features like common parameters (e.g., -Verbose, -Debug)
param(
    [switch]$AutoReboot # Parameter to automatically reboot the system if changes are made
)

# Enforce strict mode for better scripting practices.
# This helps catch common errors like using undeclared variables.
Set-StrictMode -Version Latest

#region Logging Configuration
# Define the directory where the log file will be saved.
# C:\temp is a common temporary directory.
$logDirectory = "C:\temp"
# Create a unique log file name using the current date and time.
# This ensures each script run has its own log file, preventing overwrites.
$logFileName = "WSUS_Registry_Cleanup_Log_$((Get-Date).ToString('yyyyMMdd_HHmmss')).log"
# Combine the directory and file name to get the full log file path.
$logFilePath = Join-Path -Path $logDirectory -ChildPath $logFileName

# Ensure the log directory exists. If it doesn't, create it.
# -Force allows creating the directory even if parent directories don't exist.
# -OutNull suppresses the output of New-Item.
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
    # Add-Content creates the file if it doesn't exist.
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

#region Function: Test-WsusConfigured
function Test-WsusConfigured {
    # This function checks for the presence of key WSUS registry settings that indicate
    # whether a client is configured to communicate with a WSUS server.
    $wuRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    # Check for the presence of WUServer or WUStatusServer registry values.
    # -ErrorAction SilentlyContinue prevents errors if the property doesn't exist.
    $isWUServerSet = (Get-ItemProperty -LiteralPath $wuRegPath -Name "WUServer" -ErrorAction SilentlyContinue)
    $isWUStatusServerSet = (Get-ItemProperty -LiteralPath $wuRegPath -Name "WUStatusServer" -ErrorAction SilentlyContinue)

    # Return true if either of these critical WSUS keys are found.
    return ($isWUServerSet -ne $null -or $isWUStatusServerSet -ne $null)
}
#endregion

#region Function: Remove-WindowsUpdateWUSettingsInternal
function Remove-WindowsUpdateWUSettingsInternal {
    # This function contains the core logic for removing WSUS-specific registry settings.
    # It's designed to be called internally by the script after all checks are performed.
    [CmdletBinding()] # Allows this function to use common parameters
    param()

    # Define the primary registry paths for Windows Update policies.
    # These paths store configurations related to how Windows Update behaves.
    $wuRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $auRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"

    # List of registry properties (values) to remove from the WindowsUpdate path.
    # These typically point to WSUS servers or control WSUS-specific client behavior,
    # essentially telling Windows Update, "Hey, stop looking for SCCM/WSUS!"
    $wuPropertiesToRemove = @(
        "UpdateServiceUrlAlternate",
        "FillEmptyContentUrls",
        "TargetGroupEnabled",
        "TargetGroup",
        "ElevateNonAdmins",
        "WUServer",        # The main WSUS server URL
        "WUStatusServer"   # The WSUS status server URL
    )

    # List of registry properties (values) to remove from the WindowsUpdate\AU (Automatic Updates) path.
    # These control Automatic Updates behavior when WSUS is active.
    # IMPORTANT: "NoAutoUpdate" and "AUOptions" are explicitly excluded as per requirements
    # to maintain core Windows Update behavior regardless of WSUS usage.
    $auPropertiesToRemove = @(
        "UseWUServer",                 # Indicates whether to use a WSUS server
        "DetectionFrequencyEnabled",
        "DetectionFrequency",
        "EnableFeaturedSoftware",
        "AutoInstallMinorUpdates",
        "IncludeRecommendedUpdates"
    )

    Write-Log "`nAttempting to remove specified WSUS-related registry settings. It's like breaking up with a toxic ex, but for Windows Update." -Level "INFO"

    $changesMade = $false # Flag to track if any registry modifications occurred

    # --- Process registry properties in the WindowsUpdate path ---
    if (Test-Path -Path $wuRegPath) {
        Write-Log "Processing registry path: '$wuRegPath'" -Level "INFO"
        foreach ($prop in $wuPropertiesToRemove) {
            try {
                # Check if the property exists before attempting to remove it.
                if (Get-ItemProperty -LiteralPath $wuRegPath -Name $prop -ErrorAction SilentlyContinue) {
                    Remove-ItemProperty -LiteralPath $wuRegPath -Name $prop -ErrorAction Stop # Stop on error to catch issues immediately
                    Write-Log "Successfully removed registry property: '$prop'" -Level "INFO"
                    $changesMade = $true
                } else {
                    Write-Log "Registry property '$prop' does not exist in '$wuRegPath'. Skipping. Already gone? Excellent!" -Level "WARNING"
                }
            }
            catch {
                Write-Log "Failed to remove registry property '$prop' from '$wuRegPath'. Error: $($_.Exception.Message)" -Level "ERROR"
            }
        }
    } else {
        Write-Log "Registry path '$wuRegPath' does not exist. No properties to remove from this path. Maybe SCCM never even called from here." -Level "WARNING"
    }

    # --- Process registry properties in the WindowsUpdate\AU path ---
    if (Test-Path -Path $auRegPath) {
        Write-Log "Processing registry path: '$auRegPath'" -Level "INFO"
        foreach ($prop in $auPropertiesToRemove) {
            try {
                if (Get-ItemProperty -LiteralPath $auRegPath -Name $prop -ErrorAction SilentlyContinue) {
                    Remove-ItemProperty -LiteralPath $auRegPath -Name $prop -ErrorAction Stop
                    Write-Log "Successfully removed registry property: '$prop'" -Level "INFO"
                    $changesMade = $true
                } else {
                    Write-Log "Registry property '$prop' does not exist in '$auRegPath'. Skipping. Nothing to see here, move along." -Level "WARNING"
                }
            }
            catch {
                Write-Log "Failed to remove registry property '$prop' from '$auRegPath'. Error: $($_.Exception.Message)" -Level "ERROR"
            }
        }
    } else {
        Write-Log "Registry path '$auRegPath' does not exist. No properties to remove from this path. This path was probably too busy enjoying its freedom." -Level "WARNING"
    }

    Write-Log "`nAll specified WSUS-related registry modification attempts completed. Mission accomplished, or at least attempted!" -Level "INFO"
    return $changesMade # Return boolean indicating if any changes were made
}
#endregion

# --- Main script execution flow ---

Write-Log "--- Automated Windows Update Registry Configuration Script Started ---" -Level "INFO"
Write-Log "This script helps Windows Update break free from its SCCM/WSUS chains. Log file: $logFilePath" -Level "INFO"


# Step 1: Verify Administrator privileges. Script cannot proceed without them.
# Nooo admin, no entry.
if (-not (Test-Administrator)) {
    Write-Log "This script requires Administrator privileges to perform registry modifications. Exiting." -Level "ERROR"
    Write-Host "Please right-click on the PowerShell script and select 'Run as administrator'. This isn't amateur hour." -ForegroundColor Red
    exit 1 # Exit the script with an error code
}
Write-Log "Running with Administrator privileges. Access granted!" -Level "INFO"

# Step 2: Automatically detect current WSUS usage for informational purposes.
# Just checking if SCCM was still lurking in the shadows...
$wsusIsConfigured = Test-WsusConfigured
if ($wsusIsConfigured) {
    Write-Log "WSUS configuration *was* detected (WUServer or WUStatusServer registry keys were present). Looks like we caught it red-handed!" -Level "WARNING"
} else {
    Write-Log "WSUS configuration NOT detected. This system seems to have already made its escape, or SCCM never even tried to control it here. Smart move!" -Level "INFO"
}

# Always proceed to remove the specified WSUS-related registry settings.
Write-Log "Proceeding to remove specified WSUS-related registry settings. Time to cut the cord!" -Level "INFO"
$changesMade = Remove-WindowsUpdateWUSettingsInternal # Execute the core removal function

# Provide feedback based on WSUS detection and outcome of removal.
if ($changesMade) {
    Write-Log "The script has successfully removed the specified WSUS-related settings. Freedom!" -Level "INFO"
} else {
    Write-Log "No changes were detected during removal of specified WSUS-related settings. Either they were already gone, or SCCM was just pretending." -Level "INFO"
}

Write-Log "Registry modification attempt complete. Windows Update is now free to mingle with Microsoft's public servers, or whatever its heart desires." -Level "INFO"

# Step 3: Conditional Reboot based on -AutoReboot parameter and if changes were made.
# A reboot is often needed for registry changes to take full effect.
if ($changesMade -and $AutoReboot) {
    Write-Log "AutoReboot parameter specified and changes were made. Initiating a glorious reboot! Your system needs to wake up in a new, unmanaged world." -Level "INFO"
    Restart-Computer -Force
} elseif ($changesMade -and -not $AutoReboot) {
    Write-Log "Changes were made, but -AutoReboot was not specified. Please remember to reboot manually when ready for changes to take full effect. Don't leave your system hanging!" -Level "WARNING"
} else {
    Write-Log "No changes were made to the registry, so no reboot is required. Phew, saved you a startup cycle!" -Level "INFO"
}

Write-Log "--- Script Finished ---" -Level "INFO"
Write-Host "Script completed. Check the log file at '$logFilePath' for detailed information. Because who doesn't love logs?" -ForegroundColor Green
