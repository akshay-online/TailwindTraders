param (
    [string] $PAT=$null,
    [string] $organization,
    [string] $repository,
    [string] $branchname,
    [string] $teamProject,
    [bool] $isInBuild=$true
)

function New-AzDoAuthenticationToken {
    [CmdletBinding()]
    [OutputType([object])]
    
    param (
        [string] $PersonalAccessToken
    )
    

    $accesstoken = "";
    if([string]::IsNullOrEmpty($env:System_AccessToken)) 
    {
        if([string]::IsNullOrEmpty($PAT))
        {
            throw "No token provided. Use either env:PersonalAccessToken for Localruns or use in VSTS Build/Release (System_AccessToken)"
        } 
        $userpass = ":$($PAT)"
        $encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($userpass))
        $accesstoken = "Basic $encodedCreds"
    }
    else 
    {
        $accesstoken = "Bearer $env:System_AccessToken"
    }

    return $accesstoken;
}

function Get-Repository 
{
    param
    (
     [string] $teamProject,
     [string] $repoName
    )

    $repoURL = "https://dev.azure.com/$organization/$teamProject/_apis/git/repositories?api-version=7.0"
    $response = Invoke-RestMethod -Uri $repoURL -Headers @{Authorization = $ghazdoAccessToken}   -ContentType "application/json" -Method Get 
    
    foreach($t in $($response.value))
    {
        if ($t.name -eq $repoName) 
        {
            return $t;
        }
    } 
    return $null;
}

function Run-AdvancedSecurity {
    param (
        [string] $PAT=$null,
        [string] $organization,
        [string] $repository,
        [string] $branchname,
        [string] $teamProject,
        [bool] $isInBuild=$true
    )

    if ($isInBuild) {
        $PAT = $null
        $repoID = $env:BUILD_REPOSITORY_ID
        $repository = $env:BUILD_REPOSITORY_NAME
        $teamProject = $env:SYSTEM_TEAMPROJECT
        $branchname=$env:Build_sourceBranchName
        #$organization="xpirit"
        $url = $env:System_CollectionUri
        $organization = [regex]::Match($url, "(?<=\/)[^\/]+(?=\/$)").Value
    }

    # Get Token
    $ghazdoAccessToken = New-AzDoAuthenticationToken -PersonalAccessToken $PAT


    Write-Host "Organization: $organization"
    Write-Host "Team Project: $teamProject"
    Write-Host "Repository: $repository"
    Write-Host "Branch Name: $branchname"
    Write-Host $env:System_TeamFoundationCollectionUri

    #$repoID = (Get-Repository -teamProject $teamProject -repoName $repository).id
    Write-Host "Repository ID: $repoID"


    # Call the adv security dependecies
    $CriticalDependenciesURL = "https://advsec.dev.azure.com/$($organization)/$($teamProject)/_apis/AdvancedSecurity/Repositories/$($repoID)/Alerts?criteria.alertType=1&criteria.branchName=$($branchname)&criteria.onlyDefaultBranchAlerts=true&useDatabaseProvider=true" 
    Write-Host "URL: $CriticalDependenciesURL"
    $response = Invoke-RestMethod -Uri $CriticalDependenciesURL -Headers @{Authorization = $ghazdoAccessToken}   -ContentType "application/json" -Method Get
    Write-Host "Response: $response"
    
    $filteredData = $response.value | Where-Object { $_.severity -eq "critical" }


    # check the json for high vulnerabilties
    if ($($filteredData.Count) -gt 0)
    {
        Write-Host "Found [$($filteredData.Count)] critical vulnerabilities in the branch" -ForegroundColor Red
        Write-Host "Fail Build"
        exit 1
    }
    else 
    {
        Write-Host "No critical vulnerabilities in the branch"

    }
}

Run-AdvancedSecurity -PAT $PAT -organization $organization -repository $repository -branchname $branchname -teamProject $teamProject -isInBuild $isInBuild
