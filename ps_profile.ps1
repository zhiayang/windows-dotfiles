###############################################################################
# WintellectPowerShell Module
# Copyright (c) 2010-2017 - John Robbins/Wintellect
#
# Do whatever you want with this module, but please do give credit.
###############################################################################

Set-StrictMode -version Latest

function Invoke-CmdScript
{
	param
	(
		[Parameter(Mandatory=$true,
				   Position=0,
				   HelpMessage="Please specify the command script to execute.")]
		[string] $script,
		[Parameter(Position=1)]
		[string] $parameters=""
	)

	# Save off the current environment variables in case there's an issue
	$oldVars = $(Get-ChildItem -Path env:\)
	$tempFile = [IO.Path]::GetTempFileName()

	try
	{
		## Store the output of cmd.exe. We also ask cmd.exe to output
		## the environment table after the batch file completes
		cmd /c " `"$script`" $parameters && set > `"$tempFile`" "

		if ($LASTEXITCODE -ne 0)
		{
			throw "Error executing CMD.EXE: $LASTEXITCODE"
		}

		# Before we delete the environment variables get the output into a string
		# array.
		$vars = Get-Content -Path $tempFile

		# Clear out all current environment variables in PowerShell.
		Get-ChildItem -Path env:\ | Foreach-Object {
						set-item -force -path "ENV:\$($_.Name)" -value ""
					}


		## Go through the environment variables in the temp file.
		## For each of them, set the variable in our local environment.
		$vars | Foreach-Object {
							if($_ -match "^(.*?)=(.*)$")
							{
								Set-Content -Path "env:\$($matches[1])" -Value $matches[2]
							}
						}
	}
	catch
	{
		"ERROR: $_"

		# Any problems, restore the old environment variables.
		$oldVars | ForEach-Object { Set-Item -Force -Path "ENV:\$($_.Name)" -value $_.Value }
	}
	finally
	{
		Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
	}
}

function Get-Home {
	# On Unix systems, $HOME comes with a trailing slash, unlike the Windows variant
	return $HOME.TrimEnd('/','\')
}

function Get-Provider {
	param(
		[Parameter(Mandatory = $true)]
		[string]
		$path
	)

	return (Get-Item $path -Force).PSProvider.Name
}


function Get-Drive {
	param(
		[Parameter(Mandatory = $true)]
		[System.Object]
		$dir
	)

	$provider = Get-Provider -path $dir.Path

	if($provider -eq 'FileSystem') {
		$homedir = Get-Home
		if($dir.Path.StartsWith($homedir)) {
			return '~'
		}
		elseif($dir.Path.StartsWith('Microsoft.PowerShell.Core')) {
			$parts = $dir.Path.Replace('Microsoft.PowerShell.Core\FileSystem::\\','').Split('\')
			return "$($parts[0])$pathSep$($parts[1])$pathSep"
		}
		else {
			$root = $dir.Drive.Name
			if($root) {
				return $root + ':'
			}
			else {
				return $dir.Path.Split(':\')[0] + ':'
			}
		}
	}
	else {
		return $dir.Drive.Name
	}
}

function Test-IsVCSRoot {
	param(
		[object]
		$dir
	)

	return (Test-Path -Path "$($dir.FullName)\.git") -Or (Test-Path -Path "$($dir.FullName)\.hg") -Or (Test-Path -Path "$($dir.FullName)\.svn")
}

function Test-Administrator {
	if ($PSVersionTable.Platform -eq 'Unix') {
		return (whoami) -eq 'root'
	} elseif ($PSVersionTable.Platform -eq 'Windows') {
		return $false #TO-DO: find out how to distinguish this one
	} else {
		return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')
	}
}

function Get-ShortPath {
	param(
		[Parameter(Mandatory = $true)]
		[System.Management.Automation.PathInfo]
		$dir
	)

	$provider = Get-Provider -path $dir.path

	if($provider -eq 'FileSystem') {
		$result = @()
		$currentDir = Get-Item $dir.path -Force

		while( ($currentDir.Parent) -And ($currentDir.FullName -ne (Get-Home)) ) {
			if(Test-IsVCSRoot -dir $currentDir) {
				$result = ,"$colour_vcsroot$($currentDir.Name)$colour_path" + $result
			}
			elseif($result.length -eq 0) {
				$result = ,"$colour_path$($currentDir.Name)" + $result
			}
			else {
				$result = ,"$colour_symbol…" + $result
			}

			$currentDir = $currentDir.Parent
		}
		$shortPath =  $result -join "$colour_symbol$pathSep"
		if ($shortPath) {
			$drive = (Get-Drive -dir $dir)
			return "$drive$colour_symbol$pathSep$shortPath"
		}
		else {
			if ($dir.path -eq (Get-Home)) {
				return '~'
			}
			return "$($dir.Drive.Name):"
		}
	}
	else {
		return $dir.path.Replace((Get-Drive -dir $dir), '')
	}
}







# do some magic so we can call user32 functions
Add-Type @"
	using System;
	using System.Runtime.InteropServices;
	public class User32 {
		[DllImport("user32.dll")]
		[return: MarshalAs(UnmanagedType.Bool)]
		public static extern bool ShowWindow(IntPtr hwnd, int nCmdShow);

		[DllImport("user32.dll")]
		public static extern void SwitchToThisWindow(IntPtr hwnd, bool fUnknown);

		[DllImport("user32.dll")]
		[return: MarshalAs(UnmanagedType.Bool)]
		public static extern bool BringWindowToTop(IntPtr hwnd);

		[DllImport("user32.dll")]
		[return: MarshalAs(UnmanagedType.Bool)]
		public static extern bool SetForegroundWindow(IntPtr hwnd);

		[DllImport("user32.dll")]
		public static extern IntPtr GetForegroundWindow();

		[DllImport("user32.dll")]
		public static extern int GetWindowThreadProcessId(IntPtr hWnd, out int lpdwProcessId);

		[DllImport("kernel32.dll")]
		public static extern int GetCurrentThreadId();

		[DllImport("user32.dll")]
		static extern bool AttachThreadInput(int idAttach, int idAttachTo, bool fAttach);
	}
"@



# stolen from https://www.powershellgallery.com/packages/CommonUtilities/1.2
function Switch-User
{
	[CmdletBinding()]
	Param
	(
		[Parameter(ValueFromPipeline = $true)]
		[System.Management.Automation.PSCredential]
		$Credential = [System.Management.Automation.PSCredential]::Empty,
		$CommandToRun = [String]::Empty,
		$KeepOpen = $true
	)
	process
	{
		$local:ErrorActionPreference = 'Stop'
		if ($Host.Name -ne 'ConsoleHost')
		{
			Write-Error 'This cmdlet can only be invoked from PowerShell.'
			return
		}
		$local:IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')
		$local:currentPathUnicodeBase64 = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes((Get-Location).Path))
		$local:suProcessInitCmd = '& { '
		$suProcessInitCmd += 'Set-Location -Path ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('
		$suProcessInitCmd += "'"
		$suProcessInitCmd += $currentPathUnicodeBase64
		$suProcessInitCmd += "'"
		$suProcessInitCmd += '))); '
		$suProcessInitCmd += "$CommandToRun"
		$suProcessInitCmd += "; "
		$suProcessInitCmd += '}'
		$local:suProcess = $null
		$local:currentProcess = $null
		$local:wasVisible = $true

		if (($CommandToRun -eq "") -or ($KeepOpen)) {
			$noExitArg = "-NoExit"
		}
		else {
			$noExitArg = ""
		}

		$hwnd = [User32]::GetForegroundWindow()
		$suProcess = $null

		if ($IsAdmin -and [object]::ReferenceEquals($Credential, [System.Management.Automation.PSCredential]::Empty))
		{
			$Credential = Get-Credential -Message 'Please specify the credential to run PowerShell.'
			if ($Credential -eq $null)
			{
				Write-Error 'Action cancelled by user.' -Category OperationStopped
				return
			}
		}
		if ([object]::ReferenceEquals($Credential, $null) -or [object]::ReferenceEquals($Credential, [System.Management.Automation.PSCredential]::Empty))
		{
			$suProcess = Start-Process -PassThru -FilePath 'pwsh.exe' -Verb 'runas' `
				-ArgumentList @($noExitArg, '-ExecutionPolicy', (Get-ExecutionPolicy).ToString(), '-Command', $suProcessInitCmd)

			if ($suProcess -eq $null)
			{
				return
			}
		}
		else
		{
			$suProcess = Start-Process -PassThru -FilePath 'pwsh.exe' `
				-ArgumentList @($noExitArg, '-ExecutionPolicy', (Get-ExecutionPolicy).ToString(), '-Command', $suProcessInitCmd) `
				-Credential $Credential
			if ($suProcess -eq $null)
			{
				return
			}
		}

		# hijack the other window-thread
		$curThr = [User32]::GetCurrentThreadId()
		$othThr = [User32]::GetWindowThreadProcessId([User32]::GetForegroundWindow(), [ref] $null)

		# Write-Output "cur: $curThr, oth: $othThr, su: $suProcess"
		$wasVisible = [User32]::ShowWindow($hwnd, 6)
		$suProcess.WaitForExit()

		if ($wasVisible)
		{
			[User32]::ShowWindow($hwnd, 5) | Out-Null
			[User32]::SwitchToThisWindow($hwnd, $True)
			[User32]::BringWindowToTop($hwnd) | Out-Null
			[User32]::SetForegroundWindow($hwnd) | Out-Null
		}

		$suProcess.Dispose()
		return
	}
}



# set our colours for the prompt.
$ESC = [char]27
$pathSep = '\'

$colour_reset   = "$ESC[39m"
$colour_lambda  = "$ESC[38;2;86;182;194m"
$colour_lambdaF = "$ESC[38;2;224;108;117m"
$colour_symbol  = "$ESC[38;2;115;124;140m"
$colour_user    = "$ESC[38;2;152;195;121m"
$colour_path    = "$ESC[38;2;97;175;239m"
$colour_vcsroot = "$ESC[38;2;198;120;221m"

# set colours to not be bad
Import-Module PSReadLine
Set-PSReadlineOption -Colors @{
	"Parameter" = "#abb2bf"
	"Operator" = "#e06c75"
	"Default" = "#d2d6db"
	"None" = "#d2d6db"
}


function prompt {
	$prevExitOk = $?

	$shortPath = Get-ShortPath($pwd)
	if(Test-Administrator) {
		$theUserName = "root"
	}
	else {
		$theUserName = $env:UserName
	}

	if($prevExitOk) {
		$lamb_colour = $colour_lambda
	}
	else {
		$lamb_colour = $colour_lambdaF
	}

	$promptSym = "$($lamb_colour)λ"
	$promptUser = "$colour_symbol($colour_user$theUserName$colour_symbol)"

	return "$promptSym $promptUser $colour_path$shortPath$colour_symbol > $colour_reset"
}

# alias functions
function print_pwd {
	return (Get-Location).toString()
}

function Format-FileSize() {
	param ([long]$size)
	if     ($size -gt 1099511627776)    {return [string]::Format("{0:0.0}T", $size / 1099511627776)}
	elseif ($size -gt 1073741824)       {return [string]::Format("{0:0.0}G", $size / 1073741824)}
	elseif ($size -gt 1048576)          {return [string]::Format("{0:0.0}M", $size / 1048576)}
	elseif ($size -gt 1024)             {return [string]::Format("{0:0.0}K", $size / 1024)}
	else                                {return [string]::Format("{0}", $size)}
}


function bash_ls_wrapper {
	param(
		[switch] $R,
		[switch] $l,
		[switch] $a,

		[Parameter(ValueFromRemainingArguments=$true)]
		[string[]]$dirs
	)

	if($dirs -eq $null) {
		$dirs = ,$pwd
	}

	$arguments = @{
		Recurse = $R
	}

	$things = Get-ChildItem @arguments $dirs
	if(-not $a) {
		$things = $things | Where-Object -FilterScript {$_.Name -notmatch '^\.'}
	}

	if(-not $l) {
		return $things | Format-Wide -AutoSize -GroupBy $(if($R){'Directory'}else{'None'}) -Property 'Name'
	}
	else {
		# display in a single line, then.
		return $things | Format-Table -HideTableHeaders -Property @{
			Name        = 'Mode'
			Expression  = { $_.Mode }
			Width       = 8
		} ,@{
			Name        = 'Length'
			Expression  = { "{0,7:N0}" -f (Format-FileSize($_.Length)) }
			Width       = 9
		}, @{
			Name        = 'LastWriteDate'
			Expression  = { Get-Date $_.LastWriteTime -Format 'HH:mm, dd MMM' }
			Width       = 15
		},'Name'
	}
}

function list_files {
	bash_ls_wrapper @args
}

function list_files_attr {
	bash_ls_wrapper -l -a @args
}

function su {
	Switch-User
}

function sudo {
	param(
		[switch] $keep=$false,

		[Parameter(Mandatory=$true, ValueFromRemainingArguments=$true)]
		[string[]]$Passthrough
	)

	Switch-User -Credential $null -KeepOpen $keep -CommandToRun $Passthrough
}

Set-Alias -name which -value Get-Command
Set-Alias -name pwd -value print_pwd
Set-Alias -name ls -value list_files
Set-Alias -name la -value list_files_attr

Remove-Alias md
Remove-Alias chdir

$Env:Path += ";C:\Program Files (x86)\GnuPG\bin;C:\Program Files\Git\bin;"

Write-Output ("powershell {0}.{1}.{2}" -f $PSVersionTable.PSVersion.Major, $PSVersionTable.PSVersion.Minor,
	$PSVersionTable.PSVersion.Patch)

Invoke-CmdScript "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat" | out-null
Write-Output ("vctools {0}" -f $Env:VCToolsVersion)
Write-Output ""

# start the gpg agent so git can sign commits
gpgconf --launch gpg-agent















