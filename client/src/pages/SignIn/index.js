import { useState, useEffect } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useSelector, useDispatch } from 'react-redux'
import { signIn } from '../../features/user/userSlice'
import axios from '../../api'

const Index = () => {
	const user = useSelector(state => state.user)
	const dispatch = useDispatch()
	const navigate = useNavigate()

	const [signInValue, setSignInValue] = useState({
		username: '',
		password: ''
	})

	const [errorCode, seterrorCode] = useState({
		isShow: false,
		message: ''
	})

	const onChangeSignInValue = (e) => {
		setSignInValue((prev) => ({
			...prev,
			[e.target.name]: e.target.value
		}))
	}

	const submit = async () => {
		if (!signInValue.username || !signInValue.password) {
			seterrorCode({ isShow: true, message: "Missing data!" })
			return
		}
		axios.post('/auth/signin', { username: signInValue.username, password: signInValue.password })
			.then(res => {
				if (res.data.accessToken) {
					dispatch(signIn(res.data))
					navigate("/")
				}
			})
			.catch(err => {
				seterrorCode({ isShow: true, message: err.response.data.message || "Internal Server Error" })
			})
	}

	useEffect(() => {
		if (user.user) navigate("/")
	}, [])

	return (
		<div className="flex flex-col items-center justify-center mx-auto md:h-screen lg:py-0">
			<Link to="/" className="flex items-center mb-6 text-2xl font-semibold text-gray-900">
				<img className="w-8 h-8 mr-2" src="https://flowbite.s3.amazonaws.com/blocks/marketing-ui/logo.svg" />
				Minimog
			</Link>
			<div className="w-full bg-white rounded-lg shadow dark:border md:mt-0 sm:max-w-md xl:p-0 dark:bg-gray-800 dark:border-gray-700">
				<div className="p-6 space-y-4 md:space-y-6 sm:p-8">
					<h1 className="text-xl font-bold leading-tight tracking-tight text-gray-900 md:text-2xl dark:text-white">
						Sign in to your account
					</h1>
					<div className="space-y-4 md:space-y-6" >
						<div>
							<label className="block mb-2 text-sm font-medium text-gray-900 dark:text-white">Your username</label>
							<input type="text" name="username" value={signInValue.username} onChange={onChangeSignInValue} className="bg-gray-50 border border-gray-300 text-gray-900 sm:text-sm rounded-lg focus:ring-primary-600 focus:border-primary-600 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500" />
						</div>
						<div>
							<label className="block mb-2 text-sm font-medium text-gray-900 dark:text-white">Password</label>
							<input type="password" name="password" value={signInValue.password} onChange={onChangeSignInValue} className="bg-gray-50 border border-gray-300 text-gray-900 sm:text-sm rounded-lg focus:ring-primary-600 focus:border-primary-600 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500" />
						</div>
						{errorCode.isShow &&
							<div className="px-2 py-1 text-sm text-red-700 bg-red-100 rounded-lg dark:bg-red-200 dark:text-red-800" role="alert">
								<span className="font-medium">{errorCode.message}</span>
							</div>
						}
						<div className="flex items-center justify-between">
							<div className="flex items-start">
								<div className="flex items-center h-5">
									<input type="checkbox" className="w-4 h-4 border border-gray-300 rounded bg-gray-50 focus:ring-3 focus:ring-primary-300 dark:bg-gray-700 dark:border-gray-600 dark:focus:ring-primary-600 dark:ring-offset-gray-800" />
								</div>
								<div className="ml-3 text-sm">
									<label className="text-gray-500 dark:text-gray-300">Remember me</label>
								</div>
							</div>
							<a href="#" className="text-sm font-medium text-primary-600 hover:underline dark:text-primary-500">Forgot password?</a>
						</div>
						<button onClick={submit} className="w-full text-red-500 border border-red-500 hover:bg-red-500 hover:text-white active:bg-red-600 font-bold px-3 py-1 rounded outline-none focus:outline-none ease-linear transition-all duration-150">
							Sign In
						</button>
						<p className="text-sm font-light text-gray-500 dark:text-gray-400">
							Don’t have an account yet? <Link to="/signup" className="font-medium text-primary-600 hover:underline dark:text-primary-500">Sign up</Link>
						</p>
					</div>
				</div>
			</div>
		</div>
	)
}

export default Index