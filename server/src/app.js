require('dotenv').config()
const express = require('express')
const loader = require('./app/loaders')
const http = require('http')
const { Server } = require('socket.io')

async function startServer() {
	const app = express()
	const server = http.createServer(app)
	const io = new Server(server, {
		cors: ['http://localhost:3000', 'http://localhost:3001']
	})

	await loader(app, io)

	// set port, listen for request
	server.listen(process.env.PORT, err => {
		if(err) {
			console.log(err)
			return
		}
		console.log('Server is running at PORT: ', process.env.PORT)
	})
}

startServer()
