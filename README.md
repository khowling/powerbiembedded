
## Example of Power BI Embedded nodejs website

This example webapp authenticates against Azure AD to obtain an access token, either using the interactive authorization code flow, or the non-interactive password or service principle flow (depending on environment variables - see below), then calls the Power BI API to get a list of Reports in the specified Workspace. The user can select the report specific URL to render the Embedded Content.

The Power BI workspace is specified using an environment variable

```
$env:POWERBI_GROUP_NAME = "WorkspaceName"
```

## KeyVault integration (optional)

The `master PowerBI` user authentication has also been specifically coded for a particular use-case,  so once you authenticate using the interactive flow with AAD, the app stores the `refresh token` into a KeyVault secret, therefore, allowing for continous refresh flows to keep the session current. In order to activate this (its optional), this application needs to be deployed to an Azure App Service with MSI enabled, and a KeyVault needs to be provisioned, and the following environment variables need to be setup:

```
$env:VAULT_NAME = "<vaul tname>"
$env:VAULT_SECRET_KEY = "<secret name>"
```

NOTE: The `MSI_SECRET` & `MSI_ENDPOINT` environment variables are injected into the app at runtime automattically 

##  2 modes

This example also supports the `App Owns the Data (embed token)`, and `User Owners The Data (aad token)`, modes. Its currently defaulted to the latter, but can easily changed.


## Running the App

Once cloned, you will need to setup the required environment variables to allow the application to authenticate into Azure Active Directory, and obtain a token for the PowerPI service.

## AAD

An application will need to be created in AAD to represent this application, once done, set the following environment variables:


* The Azure AD Directory (or Tenant) where your App is registered (you can see this value in the AAD blade, in "Properties"):

```
$env:CLIENT_DIRECTORY = "<Azure AD Directory Id>"
$env:CLIENT_ID = "<Azure AD Application Id>"
$env:CLIENT_SECRET = "<Azure AD Application secret>"
$env:CALLBACK_HOST = "http://<hostname where this code runs>"
```

NOTE: The `CALLBACK_HOST` value must be registered in the AAD Application "Redirect URIs" "<CALLBACK_HOST>/callback":


### Non-Interactive Authentication password Flow (optional)

To activate the non-interactive flow, pass in login credentails into the application (not recommended), you can set the following variables:

```
$env:EMBED_USERNAME = "<Azure AD username>"
$env:EMBED_PASSWORD = "<Azure AD password>"
```


## future

Currently, this example uses V1 of the Active directory endpoints, and V1 of the powebi api.  At the time of development, this was the only way to successfully display content, I will look to upgrade to V2 once it is fully supported.

Limitation: The v2.0 endpoint issues access tokens only for (1) The app that requested the token, (2) The Outlook APIs, (3) The Graph APIs.  NOT Power BI!
https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-v2-compare

### To update to v2

* Register a new `Converged` App in the 'My Applications' portal: `https://apps.dev.microsoft.com/`
* Add the scope
* 

