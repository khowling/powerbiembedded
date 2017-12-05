
# Simple example of Embedded Power BI nodejs website

This example authenticates against Azure AD, either using the interactive authorization code flow, or the non-interactive password flow, then calls the Power BI API to get a list of dashbaords in the specified group, then embeds the FRIST dashboard in the group.


## environment

### Required (upgraded to V2.0 endpoint)

The Azure AD Directory (or Tenant) where your App is registered (you can see this value in the AAD blade, in "Properties"):

```$env:CLIENT_DIRECTORY = "<Azure AD Directory Id>"```

Register a new application in the consolodated Business and Consumer portal https://apps.dev.microsoft.com, and enter the 'Application ID' here (required for all flows):

```$env:CLIENT_ID = "<Azure AD Application Id>"```


Depending on where this code is running. This value must be register in the AAD Application "Redirect URIs" "<CALLBACK_HOST>/callback":

```$env:CALLBACK_HOST = "http://<hostname where this code runs>"```

### Power BI details

Create a Power BI workspace & dashboard, and enter the Group & Dashboard Name here 

NOTE: to list powerbi groups: https://api.powerbi.com/v1.0/myorg/groups

```
$env:POWERBI_GROUP_NAME = "<Power BI Group Name>"
$env:POWERBI_DASHBOARD_NAME = "<Power BI Dashboard Name>"
```




### Required for Interactive Authentication against the Power BI Service (authorisation Flow)

* redirect user browser to :`/oauth2/v2.0/authorize` with `&response_type=code`, `&client_id`, `&redirect_uri=<callback_irl>` & `&scope=<service to access>` 

* then AAD calls back to server with code=<auth_code>

* server to POST to token endpoint `/oauth2/v2.0/token` with `&grant_type=authorization_code`, `&code=<auth_code>` & `&client_secret`  to retreive the access_token

NOTE:  access_token can be refrehed by calling the token endpoint with `&grant_type=refresh_token` & `&refresh_token`

// in the Application in AAD, under the "Keys" option, create a new key called: 'secret'

```$env:CLIENT_SECRET = "<Azure AD Application secret"```

### Required for Non-Interactive embedded Authentication against the Power BI Service (password Flow)

 * server to POST to token endpoint `/oauth2/v2.0/token` with `&grant_type=password` `&username` `&password` to retreive the access_token

```
$env:EMBED_USERNAME = "<Azure AD username"
$env:EMBED_PASSWORD = "<Azure AD password"
```


### Required for Non-Interactive Service Principle Authentication  (client_credentials Flow)

* server to POST to token endpoint `/oauth2/v2.0/token` with `&grant_type=client_credentials` `&client_secret`  to retreive the access_token