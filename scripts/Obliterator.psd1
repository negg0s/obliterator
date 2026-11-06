# Module manifest for Obliterator
@{
    RootModule = 'Obliterator.psm1'
    ModuleVersion = '0.3.0'
    GUID = 'a1b2c3d4-e5f6-47a8-9b0c-1d2e3f4a5b6c'
    Author = 'negg0s'
    CompanyName = 'negg0s'
    Copyright = '(c) 2026 negg0s. All rights reserved.'
    Description = 'PowerShell automation cmdlets and dynamic argument auto-completion for obliterator.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Get-ObliteratorBinary', 'Get-ObliteratorApp', 'Get-ObliteratorSession', 'Restore-ObliteratorSession', 'Invoke-Obliteration')
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
}
