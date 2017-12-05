const fs = require('fs'),
	url = require('url'),
	http = require('http'), https = require('https'),
	serveStatic = require('serve-static'),
	serve = serveStatic('public', {'index': ['index.html']})

const
	client_id = process.env.CLIENT_ID,
	client_secret = process.env.CLIENT_SECRET,
	callback_host = process.env.CALLBACK_HOST || 'http://localhost:5000',
	client_directory = process.env.CLIENT_DIRECTORY,
	use_sp_auth = false && client_secret != null,
	embed_username = process.env.EMBED_USERNAME,
	embed_password = process.env.EMBED_PASSWORD,
	aad_hostname = 'login.microsoftonline.com',
	powerbi_service = 'https://analysis.windows.net/group.read.all', // 'https://graph.microsoft.com/mail.send', 
	aad_token_endpoint = `/${client_directory}/oauth2/v2.0/token`,
	aad_auth_endpoint = `/${client_directory}/oauth2/v2.0/authorize`,
	powerbi_group_name = process.env.POWERBI_GROUP_NAME,
	powerbi_dashboard_name = process.env.POWERBI_DASHBOARD_NAME

let	current_token_data = {}, current_embed_dashboard = {}

const getAccessToken = (hostname, creds) => {
	console.log (`getAccessToken ("${hostname}")`)
	return new Promise((accept, reject) => {

		let flow_body
		if (!creds) {
			console.log ('client_credentials_flow (service principle)')
			flow_body = `client_id=${client_id}&scope=${encodeURIComponent('https://analysis.windows.net/')}.default&client_secret=${encodeURIComponent(client_secret)}&grant_type=client_credentials`
		} else if (creds.user && creds.password) {
			console.log ('password_flow (server-to-server, no user interaction')
			flow_body = `client_id=${client_id}&scope=${encodeURIComponent(powerbi_service)}&username=${encodeURIComponent(creds.user)}&password=${creds.password}&grant_type=password`
		} else if (creds.code) {
			console.log ('authorization_code_flow grant_type=authorization_code (supports refresh, user interaction, server can keep secret: ') //+ creds.code)
			flow_body = `client_id=${client_id}&scope=${encodeURIComponent(powerbi_service)}&code=${encodeURIComponent(creds.code)}&client_secret=${encodeURIComponent(client_secret)}&grant_type=authorization_code&redirect_uri=${encodeURIComponent(callback_host+'/callback')}`
		} else if (creds.refresh_token) {
			console.log ('refresh_flow grant_type=refresh_token')
			flow_body = `client_id=${client_id}&scope=${encodeURIComponent(powerbi_service)}&refresh_token=${encodeURIComponent(creds.refresh_token)}&grant_type=refresh_token`
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
						console.log ('successfully updated "current_token_data": ')// + rawData)
						current_token_data = JSON.parse(rawData)
						accept()
					}
				})

			}).on('error', (e) => {
				reject({code: 400, message: e})
			})
		authcode_req.write(flow_body)
		authcode_req.end()
	})
}


const getDashboard = (token) => {
	console.log ('getDashboard ()')
	return new Promise((accept, reject) => {


		https.get({
			hostname: 'api.powerbi.com',
			path: `/v1.0/myorg/groups`,
			headers: {
				"Authorization": `Bearer ${token}`
			}
		}, (dres) => {
			let rawData = '';
			dres.on('data', (d) => {
				rawData+= d
			});

			dres.on('end', () => {
				if(!(dres.statusCode === 200 || dres.statusCode === 201)) {
					console.log (`getDashboard error ${dres.statusCode} : ${dres.statusMessage} : ${rawData}`)
					reject ({code: dres.statusCode, message: dres.statusMessage})
				} else {

					let groups = JSON.parse(rawData).value;
					console.log (`successfully got all groups ${JSON.stringify(groups)}`)

					let selected_group = groups.find(g => g.name == powerbi_group_name)
					if (!selected_group) {
						reject({code: 400, message: `cannot find powerbi group ${powerbi_group_name} in subscription`})
					} else {

						https.get({
							hostname: 'api.powerbi.com',
							path: `/v1.0/myorg/groups/${selected_group.id}/dashboards`,
							headers: {
								"Authorization": `Bearer ${token}`
							}
						}, (dres) => {
							let rawData = '';
							dres.on('data', (d) => {
								rawData+= d
							});
				
							dres.on('end', () => {
								if(!(dres.statusCode === 200 || dres.statusCode === 201)) {
									console.log (`getDashboard error ${dres.statusCode} : ${dres.statusMessage} : ${rawData}`)
									reject ({code: dres.statusCode, message: dres.statusMessage})
								} else {
									let dashboards = JSON.parse(rawData).value;
									console.log (`successfully got all dashboards ${JSON.stringify(dashboards)}`)

									let selected_dashboard = dashboards.find(g => g.displayName == powerbi_dashboard_name)
									if (!selected_dashboard) {
										reject({code: 400, message: `cannot find powerbi dashboard ${powerbi_dashboard_name} in subscription`})
									} else {
										current_embed_dashboard = selected_dashboard
										accept()
									}
								}
							})
							
						}).on('error', (e) => {
							console.log ('getDashboard error ' + JSON.stringify(e))
							reject({code: 400, message: e})
						})

					}
					
				}
			})
			
		}).on('error', (e) => {
			console.log ('getDashboard error ' + JSON.stringify(e))
			reject({code: 400, message: e})
		})
	})
}
// HTTP Server to accept incomming MPEG-TS Stream from ffmpeg
var port = process.env.PORT || 5000,
	httpServer = http.createServer( (request, response) => {
	serve(request, response, () => {
		
		if (request) {
			
			let req_url = url.parse(request.url)
			console.log ('checking ')
			if (req_url.pathname === "/login") {
				console.log ('got login')
				let code_url = `https://${aad_hostname}${aad_auth_endpoint}?client_id=${client_id}&redirect_uri=${encodeURIComponent(callback_host+'/callback')}&scope=${encodeURIComponent(powerbi_service)}&response_type=code&prompt=consent`
				console.log (`url: ${code_url}`)
				response.writeHead(302, {Location: code_url})
				response.end();
			} else if (req_url.pathname === "/callback") {
				console.log ('/callback - looking for authorisation code')
				let params = new Map()
				req_url.query.split('&').forEach((p) => { let kv = p.split('='); params.set(kv[0], kv[1])})
				if (params.has('code')) {
					let code = params.get('code')
					console.log ('/callback - got code, calling getAccessToken (authflow)')
					getAccessToken (aad_hostname, {code: code}).then(() => {
						
						getDashboard(current_token_data.access_token).then (() => {
							response.writeHead(301, {Location: "/"});
							response.end();
						}, (err) => {
							console.log ('getDashboard error ' + err.message)
							response.writeHead(err.code, err.message) 
							response.end()
						})
					}, (err) => {
						console.log ('getAccessToken error ' + err.message)
						response.writeHead(err.code, err.message) 
						response.end()
					})
				} else {
					response.writeHead(400, 'no code') ;
					response.end();
				}
			} else if (req_url.pathname === "/aadauth") {
				if (request.method === "POST") {
					console.log ('NOT USED! getting aad auth token')

					let bodycreds = ''
					request.on('data', chunk => {
						bodycreds+= chunk
					});
					request.on('end', () => {
						console.log(`No more data ${bodycreds}`);
						response.writeHead(400, "not longer used") 
						response.end()
					})
				} else { // GET
					console.log ('/aadauth - GET')
					if(current_token_data.access_token && current_embed_dashboard.embedUrl) {
						console.log ('/aadauth - already got access_token and dashbaord, do we need to refresh?')
						if (current_token_data.refresh_token) {
							// refresh
							getAccessToken (aad_hostname, {refresh_token: current_token_data.refresh_token}).then(() => {
								response.end(JSON.stringify(Object.assign({embed_token: current_token_data.access_token}, current_embed_dashboard)))
							}, (err) => {
								console.log ('getAccessToken error ' + err.message)
								response.writeHead(err.code, err.message) 
								response.end()
							})
						} else {
							response.end(JSON.stringify(Object.assign({embed_token: current_token_data.access_token}, current_embed_dashboard)))
						}
					} else if (embed_username && embed_password){
						console.log ('/aadauth - got embedded credentials, use password flow')
						getAccessToken (aad_hostname, {user: embed_username, password: embed_password}).then(() => {

							getDashboard(current_token_data.access_token).then (() => {
								response.end(JSON.stringify(Object.assign({embed_token: current_token_data.access_token}, current_embed_dashboard)))
							}, (err) => {
								console.log ('getDashboard error ' + err.message)
								response.writeHead(err.code, err.message) 
								response.end()
							})
						}, (err) => {
							console.log ('getAccessToken error ' + err.message)
							response.writeHead(err.code, err.message) 
							response.end()
						})
					} else if (use_sp_auth) {
						console.log ('/aadauth - SP Auth')
						getAccessToken (aad_hostname).then(() => {
							getDashboard(current_token_data.access_token).then (() => {
								response.end(JSON.stringify(Object.assign({embed_token: current_token_data.access_token}, current_embed_dashboard)))
							}, (err) => {
								response.writeHead(err.code, err.message) 
								response.end()
							})
						})
					} else {
						console.log ('/aadauth - send url to initialite interactive authorization flow')
						response.end('{}')
					}  
				}
			} else {
				response.writeHead(404) ;
				response.end();
			}
		}
	})
	
}).listen(port);
console.log (`listening to port ${port}`)

