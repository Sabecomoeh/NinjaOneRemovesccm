# Function to check for administrator privileges
function Test-IsAdministrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# --- Logging Configuration ---
# Define the directory where the log file will be saved.
$logDirectory = "C:\temp"
# Create a unique log file name using the current date and time.
$logFileName = "SCCM_Removal_Log_$((Get-Date).ToString('yyyyMMdd_HHmmss')).log"
# Combine the directory and file name to get the full log file path.
$logFilePath = Join-Path -Path $logDirectory -ChildPath $logFileName

# Ensure the log directory exists. If it doesn't, create it.
if (-not (Test-Path $logDirectory -PathType Container)) {
    Write-Host "Log directory '$logDirectory' not found, creating it." -ForegroundColor Yellow
    New-Item -Path $logDirectory -ItemType Directory -Force | Out-Null
}

# Function to write messages to both the console and the log file.
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO" # Accepted levels: INFO, WARNING, ERROR
    )
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $logEntry = "$timestamp [$Level] $Message"
    
    # Append the log entry to the log file.
    Add-Content -Path $logFilePath -Value $logEntry

    # Display the message on the console with appropriate coloring.
    switch ($Level) {
        "INFO"    { Write-Host $Message -ForegroundColor Green }
        "WARNING" { Write-Host $Message -ForegroundColor Yellow }
        "ERROR"   { Write-Host $Message -ForegroundColor Red }
        Default   { Write-Host $Message } # Default color for unknown levels
    }
}

# --- Script Start ---
Write-Log "--- SCCM Removal Script Started ---"
Write-Log "Log file created at: $logFilePath"

# Check if running as administrator
if (-not (Test-IsAdministrator)) {
    Write-Log "This script needs to be run with Administrator privileges." -Level "ERROR"
    Write-Host "Please right-click on the PowerShell script and select 'Run as administrator'." -ForegroundColor Red
    Exit 1 # Exit the script if not running with admin rights
}
Write-Log "Running with Administrator privileges."

# Define the path to the CCMSetup directory and executable.
$ccmSetupDirectory = "C:\windows\ccmsetup"
$ccmSetupExePath = Join-Path -Path $ccmSetupDirectory -ChildPath "ccmsetup.exe"

Write-Log "Attempting to access and take ownership of '$ccmSetupDirectory'..."

try {
    # Attempt to access the directory first.
    # This action can trigger a UAC prompt if needed to gain initial access,
    # acting as an implicit "click here to get access" step.
    # -ErrorAction Stop ensures that any access denied error is caught by the catch block.
    Get-ChildItem -LiteralPath $ccmSetupDirectory -ErrorAction Stop | Out-Null
    Write-Log "Successfully accessed '$ccmSetupDirectory'." -Level "INFO"
}
catch [System.UnauthorizedAccessException] {
    # This block executes if Get-ChildItem failed due to an access denied error.
    Write-Log "Initial access denied to '$ccmSetupDirectory'. Attempting to take ownership and grant full control." -Level "WARNING"
    
    try {
        # Take ownership of the directory.
        Write-Log "Taking ownership of '$ccmSetupDirectory'..."
        # icacls is used to modify file system permissions.
        # /inheritance:r - Removes inherited permissions and replaces them with a copy of current explicit permissions.
        # /T - Applies the operation to all subfolders and files.
        # /C - Continues on file errors (for robustness).
        # /Q - Suppresses success messages (quiet mode).
        # /grant "$env:USERNAME`:(F)" - Grants full control (F) to the current user.
        $takeOwnershipResult = icacls $ccmSetupDirectory /inheritance:r /T /C /Q /grant "$env:USERNAME`:(F)" 2>&1
        
        # Check the exit code of icacls to determine if the operation was successful.
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Failed to take ownership of '$ccmSetupDirectory'. icacls returned exit code: $LASTEXITCODE" -Level "ERROR"
            Write-Log "icacls Output for ownership attempt: $takeOwnershipResult" -Level "ERROR"
            Write-Host "Please ensure you have necessary permissions even as administrator, or manually take ownership." -ForegroundColor Red
            Exit 1
        }
        Write-Log "Ownership taken successfully." -Level "INFO"

        # Grant full control to the Administrators group.
        Write-Log "Granting full control to Administrators group on '$ccmSetupDirectory'..."
        # /grant "Administrators:F" - Grants full control (F) to the built-in Administrators group.
        $grantControlResult = icacls $ccmSetupDirectory /grant "Administrators:F" /T /C /Q 2>&1
        
        # Check the exit code for the grant operation.
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Failed to grant full control to Administrators on '$ccmSetupDirectory'. icacls returned exit code: $LASTEXITCODE" -Level "ERROR"
            Write-Log "icacls Output for grant attempt: $grantControlResult" -Level "ERROR"
            Write-Host "You may need to manually adjust permissions." -ForegroundColor Red
            Exit 1
        }
        Write-Log "Full control granted to Administrators." -Level "INFO"

        # Verify access again after modifying permissions.
        Get-ChildItem -LiteralPath $ccmSetupDirectory -ErrorAction Stop | Out-Null
        Write-Log "Successfully gained access to '$ccmSetupDirectory' after modifying permissions." -Level "INFO"

    }
    catch {
        # Catch any errors that occur during the ownership/granting process.
        Write-Log "An error occurred while attempting to gain access to '$ccmSetupDirectory': $($_.Exception.Message)" -Level "ERROR"
        Write-Host "Please ensure the path is correct and you have sufficient permissions." -ForegroundColor Red
        Exit 1
    }
}
catch {
    # Catch any unexpected errors during the initial directory access attempt.
    Write-Log "An unexpected error occurred while trying to access '$ccmSetupDirectory': $($_.Exception.Message)" -Level "ERROR"
    Write-Host "Please check the path and try again." -ForegroundColor Red
    Exit 1
}

# --- Uninstall CCMSetup ---
Write-Log "Attempting to uninstall CCMSetup using explicit path '$ccmSetupExePath'..."
try {
    # Start the uninstallation process.
    # -FilePath: Specifies the path to the executable.
    # -ArgumentList: Passes the "/uninstall" argument to ccmsetup.exe.
    # -Wait: Waits for the process to complete before continuing the script.
    # -NoNewWindow: Prevents a new console window from opening for the process.
    # -PassThru: Returns a process object, allowing us to inspect its properties like ID and ExitCode.
    $process = Start-Process -FilePath $ccmSetupExePath -ArgumentList "/uninstall" -Wait -NoNewWindow -PassThru
    Write-Log "CCMSetup uninstallation command issued. Process ID: $($process.Id)." -Level "INFO"
    Write-Log "Please monitor for any prompts or progress related to the uninstallation."

    # Check and log the exit code of the uninstallation process.
    if ($process.HasExited) {
        Write-Log "CCMSetup uninstallation process exited with code: $($process.ExitCode)." -Level "INFO"
        if ($process.ExitCode -ne 0) {
            Write-Log "CCMSetup uninstallation process reported a non-zero exit code, indicating potential issues." -Level "WARNING"
        }
    } else {
        Write-Log "CCMSetup uninstallation process is still running or its exit code is not immediately available (should not happen with -Wait)." -Level "WARNING"
    }
}
catch {
    # Catch any errors that occur during the execution of ccmsetup.exe.
    Write-Log "An error occurred while trying to run '$ccmSetupExePath /uninstall': $($_.Exception.Message)" -Level "ERROR"
    # Convert the exception object to a string for more detailed logging.
    Write-Log "Ensure the file exists and is executable. Full Error details: $($_.Exception | Select-Object * | Out-String)" -Level "ERROR"
    Write-Host "Ensure the file exists and is executable. Error details: $($_.Exception | Select-Object * | Format-List)" -ForegroundColor Red
    Exit 1
}

Write-Log "--- Script completed. ---"
Write-Host "Script completed. Check the log file at '$logFilePath' for detailed information." -ForegroundColor Green

<#
+-------------------+
|     SCCM Install  |
|     (REMOVED)     |
|                   |
|-------------------|
| ||||||||||||||||| |
| ||||||||||||||||| |
+-------------------+
        \ | /
         \|/
          V
       (GONE)
#>
