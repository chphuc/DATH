import { Fragment } from 'react'
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import DefaultLayout from './layouts/DefaultLayout'
import { publicRoutes } from './routes'

import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import { useState, useEffect } from 'react'
import io from 'socket.io-client'
import SocketContext from './contexts/socket';

function App() {
	const [ socket, setSocket ] = useState(null)
  
	useEffect(() => {
	  const newSocket = io('http://localhost:8080')
	  setSocket(newSocket)
	  
	  return () => {
		setSocket(null)
		newSocket.close()
	  }
	}, [])

	return (
		<SocketContext.Provider value={socket}>
			<Router>
				<div className="App">
					<ToastContainer />
					<Routes>
						{publicRoutes.map((route, index) => {
							const Page = route.component;
							let Layout = DefaultLayout;

							if (route.layout) {
								Layout = route.layout;
							} else if (route.layout === null) {
								Layout = Fragment;
							}
							return (
								<Route
									key={index}
									path={route.path}
									element={
										<Layout>
											<Page />
										</Layout>
									}
								/>
							);
						})}
					</Routes>
				</div>
			</Router>
		</SocketContext.Provider>
	);
}

export default App;
