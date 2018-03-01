const fs = require('fs'),
	url = require('url'),
	http = require('http'), https = require('https'),
	express = require('express')

var app = express();
app.use(express.static('public'))

app.set('view engine', 'ejs');

const
	secret = process.env.SECRET,
	SECRET_NAME = process.env.VAULT_SECRET_KEY,
	VAULT_NAME = process.env.VAULT_NAME,
	client_id = process.env.CLIENT_ID,
	client_secret = process.env.CLIENT_SECRET,
	callback_host = process.env.CALLBACK_HOST || 'http://localhost:5000',
	client_directory = process.env.CLIENT_DIRECTORY,
	use_sp_auth = false && client_secret != null,
	embed_username = process.env.EMBED_USERNAME,
	embed_password = process.env.EMBED_PASSWORD,
	aad_hostname = 'login.microsoftonline.com',
	pbi_hostname = 'api.powerbi.com',
	powerbi_service_resource_v1 = 'https://analysis.windows.net/powerbi/api',
	powerbi_service_scope_v2 = 'https://graph.microsoft.com/mail.send', 
	aad_token_endpoint = `/${client_directory}/oauth2/token`,
	aad_auth_endpoint = `/${client_directory}/oauth2/authorize`,
	aad_token_endpoint_v2 = `/${client_directory}/oauth2/v2.0/token`,
	aad_auth_endpoint_v2 = `/${client_directory}/oauth2/v2.0/authorize`,
	powerbi_group_name = process.env.POWERBI_GROUP_NAME

let	current_token_data

const getAccessToken = (hostname, creds) => {
	console.log (`getAccessToken...`)
	return new Promise((accept, reject) => {

		let flow_body
		if (!creds) {
			console.log ('getAccessToken - client_credentials_flow (service principle)')
			flow_body = `client_id=${client_id}&scope=${encodeURIComponent('https://analysis.windows.net/')}.default&client_secret=${encodeURIComponent(client_secret)}&grant_type=client_credentials`
		} else if (creds.user && creds.password) {
			console.log ('getAccessToken - password_flow (server-to-server, no user interaction')
			flow_body = `client_id=${client_id}&resource=${encodeURIComponent(powerbi_service_resource_v1)}&username=${encodeURIComponent(creds.user)}&password=${creds.password}&grant_type=password`
		} else if (creds.code) {
			console.log ('getAccessToken - authorization_code_flow grant_type=authorization_code (supports refresh, user interaction, server can keep secret: ') //+ creds.code)
			flow_body = `client_id=${client_id}&resource=${encodeURIComponent(powerbi_service_resource_v1)}&code=${encodeURIComponent(creds.code)}&client_secret=${encodeURIComponent(client_secret)}&grant_type=authorization_code&redirect_uri=${encodeURIComponent(callback_host+'/callback')}`
		} else if (creds.refresh_token) {
			console.log ('getAccessToken - refresh_flow grant_type=refresh_token')
			flow_body = `client_id=${client_id}&resource=${encodeURIComponent(powerbi_service_resource_v1)}&client_secret=${encodeURIComponent(client_secret)}&refresh_token=${encodeURIComponent(creds.refresh_token)}&grant_type=refresh_token`
		}

		let	authcode_req = https.request({
				hostname: hostname,
				path: aad_token_endpoint,
				method: 'POST',
				headers: {
					'Content-Type': "application/x-www-form-urlencoded",
					'Content-Length': Buffer.byteLength(flow_body)
				}
			}, (res) => {
				let rawData = '';
				res.on('data', (chunk) => {
					rawData += chunk
				})

				res.on('end', () => {
					if (res.statusCode === 301 || res.statusCode === 302) {
						getAccessToken (url.parse(res.headers.location).hostname, creds).then((succ) => accept(succ), (err) => reject(err))
					} else if(!(res.statusCode === 200 || res.statusCode === 201)) {
						reject({code: res.statusCode, message: rawData})
					} else {
						let authdata = JSON.parse(rawData)
						console.log (`getAccessToken - Successfully got token_data, updating global "current_token_data"`) //:  + ${rawData}`)
						current_token_data = authdata

						// store refresh_token in vault
						if (authdata.refresh_token && process.env.MSI_ENDPOINT && process.env.MSI_SECRET) {
							let keyvault_token_request = Object.assign(url.parse(`${process.env.MSI_ENDPOINT}/?resource=${encodeURIComponent("https://vault.azure.net")}&api-version=2017-09-01`), {headers: {"secret": process.env.MSI_SECRET }})
							console.log (`getAccessToken - got MSI_ENDPOINT, storing refresh_token`) //  ${JSON.stringify(keyvault_token_request)}`)
							http.get(keyvault_token_request, (msi_res) => {
								let msi_data = '';
								msi_res.on('data', (d) => {
									msi_data+= d
								});
					
								msi_res.on('end', () => {
									console.log (`msi end ${msi_res.statusCode}`)
									if(msi_res.statusCode === 200 || msi_res.statusCode === 201) {
										let keyvault_access = JSON.parse(msi_data),
											request_body = JSON.stringify({"value": authdata.refresh_token })
											
										console.log (`getAccessToken - writing to keyvault_access,  body: ${request_body}`)

										let putreq = https.request({
											method: "PUT",
											hostname : `${VAULT_NAME}.vault.azure.net`,
											path : `/secrets/${SECRET_NAME}?api-version=2016-10-01`,
											headers: {
												"Authorization": `${keyvault_access.token_type} ${keyvault_access.access_token}`,
												'Content-Type': "application/json",
												'Content-Length': Buffer.byteLength(request_body)
											}}, (res) => {
												let vault_data = '';
												res.on('data', (chunk) => {
													vault_data += chunk
												})
							
												res.on('end', () => {
													console.log (`write secret ${res.statusCode} : ${vault_data}`)
													if (res.statusCode === 200) {
														console.log ("getAccessToken - successfully stored refresh token")
														accept(authdata)
													} else {
														console.error(`Got vault setSecret error: ${res.statusCode}`)
														reject({code: res.statusCode, message: `Got vault setSecret error ${vault_data}`})
													}
												
												})
											}).on('error', (e) => {
												console.error(`Got vault setSecret error: ${e.message}`);
												reject({code: 400, message: `vault setSecret error ${e.message}`})
											});
										putreq.write(request_body);
										putreq.end();
									} else {
										console.error(`Got MSI error: ${msi_res.statusCode}`);
										reject({code: msi_res.statusCode, message: msi_data})
									}
								})
							}).on('error', (e) => {
								console.error(`Got MSI error: ${e.message}`)
								reject({code: 400, message: `Got MSI error ${e.message}`})
							});
							
						} else {
							console.log ("getAccessToken - no MSI, not storing refresh_token")
							accept(authdata)
						}
					}
				})

			}).on('error', (e) => {
				reject({code: 400, message: e})
			})
		authcode_req.write(flow_body)
		authcode_req.end()
	})
}



const getDashboard = (did = null) => {
	console.log (`getDashboard - dashboard ${did}`) // -  ${current_token_data.access_token}`)
	return new Promise((accept, reject) => {

		https.get({
			hostname: pbi_hostname,
			path: `/v1.0/myorg/groups`,
			headers: {
				"Authorization": `Bearer ${current_token_data.access_token}`
			}
		}, (dres) => {
			let rawData = '';
			dres.on('data', (d) => {
				rawData+= d
			});

			dres.on('end', () => {
				if (dres.statusCode === 403) {
					// access_token expired
					console.log ('getDashboard - got 403, do we need to refresh?')
					if (current_token_data.refresh_token) {
						getAccessToken (aad_hostname, {refresh_token: current_token_data.refresh_token}).then((auth) => {
							console.log ('getDashboard - call getDashbaord again with refreshed token')
							getDashboard (did).then((succ) => accept(succ), (err) => reject(err))
						}, (err) => {
							console.log ('getDashboard refresh failed, rejecting with:  ' + err.message)
							reject (err)
						})
					} else {
						reject ({code: `getDashboard ${dres.statusCode}`, message: dres.statusMessage})
					}

				} else if (!(dres.statusCode === 200 || dres.statusCode === 201)) {
					console.log (`getDashboard http error ${dres.statusCode} : ${dres.statusMessage} : ${rawData}`)
					reject ({code: `getDashboard ${dres.statusCode}`, message: dres.statusMessage})
				} else {

					let groups = JSON.parse(rawData).value;
					console.log (`successfully got all groups: ${groups.length}`) // ${JSON.stringify(groups)}`)

					let selected_group = groups.find(g => g.name == powerbi_group_name)
					if (!selected_group) {
						reject({code: 400, message: `cannot find powerbi group ${powerbi_group_name} in subscription`})
					} else {

						https.get({
							hostname: pbi_hostname,
							path: `/v1.0/myorg/groups/${selected_group.id}/reports`,
							headers: {
								"Authorization": `Bearer ${current_token_data.access_token}`
							}
						}, (dres) => {
							let rawData = '';
							dres.on('data', (d) => {
								rawData+= d
							});
				
							dres.on('end', () => {
								if(!(dres.statusCode === 200 || dres.statusCode === 201)) {
									console.log (`getDashboard error ${dres.statusCode} : ${dres.statusMessage} : ${rawData}`)
									reject ({code: `getDashboard - ${dres.statusCode}`, message: dres.statusMessage})
								} else {
									let dashboards = JSON.parse(rawData).value;
									//console.log (`successfully got all dashboards: ${JSON.stringify(dashboards)}`)
									if (did) {
										let selected_dashboard = dashboards.find(g => g.id == did)
										if (!selected_dashboard) {
											reject({code: 400, message: `cannot find powerbi dashboard ${did} in subscription`})
										} else {
											// object literal shorthand notation
											accept({selected_group, selected_dashboard})
										}
									} else {
										console.log (`getDashboard - returning ${dashboards.length} dashboards`)
										accept(dashboards)
									}
								}
							})
							
						}).on('error', (e) => {
							console.log ('getDashboard on error ' + JSON.stringify(e))
							reject({code: `getDashboard: 400`, message: e})
						})

					}
				}
			})
			
		}).on('error', (e) => {
			console.log ('getDashboard error ' + JSON.stringify(e))
			reject({code: `getDashboard: 400`, message: e})
		})
	})
}

let authenticated = false

const setCurrentAccessToken = () => {
	return new Promise((accept, reject) => {
		if (current_token_data) {
			console.log (`setCurrentAccessToken -got it from current_token_data`)
			accept()
		} else {
			// store refresh_token in vault
			if (process.env.MSI_ENDPOINT && process.env.MSI_SECRET) {
				let keyvault_token_request = Object.assign(url.parse(`${process.env.MSI_ENDPOINT}/?resource=${encodeURIComponent("https://vault.azure.net")}&api-version=2017-09-01`), {headers: {"secret": process.env.MSI_SECRET }})
				console.log (`setCurrentAccessToken - got MSI_ENDPOINT, restoring refresh_token`) //  ${JSON.stringify(keyvault_token_request)}`)
				http.get(keyvault_token_request, (msi_res) => {
					let msi_data = '';
					msi_res.on('data', (d) => {
						msi_data+= d
					});
		
					msi_res.on('end', () => {
						console.log (`msi end ${msi_res.statusCode}`)
						if(msi_res.statusCode === 200 || msi_res.statusCode === 201) {
							let keyvault_access = JSON.parse(msi_data)
							let keyvaut_secret_request = Object.assign(url.parse(`https://${VAULT_NAME}.vault.azure.net/secrets/${SECRET_NAME}/?api-version=2016-10-01`), {headers: {
								"Authorization": `${keyvault_access.token_type} ${keyvault_access.access_token}`}})
							
							console.log (`setCurrentAccessToken - getting from keyvault`)

							https.get(keyvaut_secret_request, (secret_res) => {
								let vault_data = '';
								secret_res.on('data', (chunk) => {
									vault_data += chunk
								})
			
								secret_res.on('end', () => {
									console.log (`get secret ${secret_res.statusCode} : ${vault_data}`)
									if (secret_res.statusCode === 200) {
										console.log ("setCurrentAccessToken - successfully got  refresh token from vault")
										let keyvault_secret = JSON.parse(vault_data)

										getAccessToken (aad_hostname, {refresh_token: keyvault_secret.value}).then((auth) => {
											console.log ('setCurrentAccessToken -  successfully got access token!')
											accept()
										}, (err) => {
											console.log ('setCurrentAccessToken refresh failed, rejecting with:  ' + err.message)
											reject (err)
										})
									} else {
										console.error(`Got vault setSecret error: ${secret_res.statusCode}`)
										reject({code: secret_res.statusCode, message: `Got vault setSecret error ${vault_data}`})
									}
								
								})
							}).on('error', (e) => {
								console.error(`Got vault setSecret error: ${e.message}`);
								reject({code: 400, message: `vault setSecret error ${e.message}`})
							});

						} else {
							console.error(`Got MSI error: ${msi_res.statusCode}`);
							reject({code: msi_res.statusCode, message: msi_data})
						}
					})
				}).on('error', (e) => {
					console.error(`Got MSI error: ${e.message}`)
					reject({code: 400, message: `Got MSI error ${e.message}`})
				});
				
			} else {
				console.log ("setCurrentAccessToken - no MSI")
				reject()
			}
		}
	})
}

app.get('/auth', function(req, res) {
	console.log ('/auth ---- called')
	res.redirect(`https://${aad_hostname}${aad_auth_endpoint}?client_id=${client_id}&redirect_uri=${encodeURIComponent(callback_host+'/callback')}&resource=${encodeURIComponent(powerbi_service_resource_v1)}&response_type=code&prompt=consent`)
})

app.get('/', function(req, res) {
	console.log ('/ ------ called')
	if (!secret || url.parse(req.url, true).query["secret"] == secret) {
		setCurrentAccessToken().then (()=> {
			getDashboard().then ((dashbaords) => {
				res.render('result', {status: "Successfully Authenticated", message: "Now call with https://<host>/db/<dashboard Id>", dashbaords: dashbaords})
			}, (err) => {
				res.render('result',{status: "ERROR Retreiving Dashbaords", message: `${err.code}: ${err.message}`})
			})
		}, (err) => {
			res.render('result', {status: "Not Authenticated", message: `${url.parse(req.url, true).query["message"] || JSON.stringify(err) || ""} Press Authenticate to login with PowerBI Pro Master User`})
		})
	} else {
		res.render('result', {status: "Not Authorised", message: "See your admin to get authorised"}) 
	}
})

const generateEmbedToken = (selected_group, selected_dashboard) => {
  return new Promise((accept, reject) => {
	let	embedtoken_body = JSON.stringify({
		"accessLevel": "View"
	}),
	embedtoken_req = https.request({
		hostname: pbi_hostname,
		path: `/v1.0/myorg/groups/${selected_group.id}/reports/${selected_dashboard.id}/GenerateToken`,
		headers: {
			"Authorization": `Bearer ${current_token_data.access_token}`,
			"Content-Type": "application/json",
			'Content-Length': Buffer.byteLength(embedtoken_body)
		},
		method: 'POST',
	}, (res) => {
		let rawData = '';
		res.on('data', (chunk) => {
			rawData += chunk
		})

		res.on('end', () => {
			if(!(res.statusCode === 200 || res.statusCode === 201)) {
				reject({code: res.statusCode, message: rawData})
			} else {
				accept(JSON.parse(rawData))
			}
		})
	}).on('error', (e) => {
		reject({code: 400, message: e})
	})
	embedtoken_req.write(embedtoken_body)
	embedtoken_req.end()
  })
}


app.get('/db/:dashboard', function(req, res) {
	let did = req.params.dashboard
	console.log ('/db ---- called')
	if (!did) {
		res.render('result',{status: "ERROR", message: "Please provide dashboard Id"})
	} else {
		// get access_token
		setCurrentAccessToken().then (()=> {
			// get dashboard embedUrl
			getDashboard(did).then (({selected_group, selected_dashboard}) => {
				
				if (false) { 	
					// App Owns Data, (typically an ISV scenario), a "Power BI Embedded" license is required
					// get embed token for powerbi content, You will need to configure the embed token to account for the user and role
					generateEmbedToken (selected_group, selected_dashboard).then(embedtoken => {
						//console.log (`got embedToken : ${JSON.stringify(embedtoken)}`)
						res.render('embedded', {access_token: "", embed_token: embedtoken.token, embed_url: selected_dashboard.embedUrl})
					}, (err) => {
						res.render('result',{status: "ERROR", message: `${err.code}: ${err.message}`})
					})
				} else { 		
					// User Owns Data, users login as themselfs, they have powerbi pro licences, and are inside your organisation
					res.render('embedded', {embed_token: "", access_token: current_token_data.access_token, embed_url: selected_dashboard.embedUrl})
				}
			}, (err) => {
				res.render('result',{status: "ERROR", message: `${err.code}: ${err.message}`})
			})
		}, (err) => {
			res.redirect(`https://${aad_hostname}${aad_auth_endpoint}?client_id=${client_id}&redirect_uri=${encodeURIComponent(callback_host+'/callback')}&resource=${encodeURIComponent(powerbi_service_resource_v1)}&response_type=code&prompt=consent&state=${did}`)
		})		
	}
})

app.get('/callback', function(req, res) {
	console.log (`/callback - looking for authorisation code`)
	let code = url.parse(req.url, true).query["code"]

	if (code) {
		
		console.log ('/callback - got code, calling getAccessToken (authflow)')
		getAccessToken (aad_hostname, {code: code}).then((auth) => {
			console.log ('success, got token ')
			res.redirect (`/` + (secret && `?secret=${secret}` || ''))
			//res.render('result', {status: "SUCCESS", message: "Authorised, now call with https://<host>/dashboard/<dashboard Id>"})
			
		}, (err) => {
			current_token_data = null
			console.log ('error, cannot get token: ' + err.message)
			res.redirect (`/?message=${encodeURIComponent(`${err.code}: ${err.message}`)}`)
			//res.render('result', {status: "ERROR", message: `${err.code}: ${err.message}`})
		})
	} else {
		current_token_data = null
		console.log ('callback error: No authorisation code')
		res.redirect (`/?message=${encodeURIComponent("No authorisation code")}`)
		//res.render('result',  {status: "ERROR", message: `no code`})
	}
})

const port = process.env.PORT || 5000
app.listen(port);
console.log('port is the magic port');