import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import axios from '../../api'

const Index = () => {
    const navigate = useNavigate()

    const [signUpValue, setSignUpValue] = useState({
        userName: '',
        email: '',
        password: '',
        repeatPassword: '',
    })

    const [errorCode, seterrorCode] = useState({
        isShow: false,
        message: ''
    })

    const onChangeSignUpValue = (e) => {
        setSignUpValue((prev) => ({
            ...prev,
            [e.target.name]: e.target.value
        }))
    }

    const handleSignUp = () => {
        if (!signUpValue.userName || !signUpValue.email || !signUpValue.password || !signUpValue.repeatPassword) {
            seterrorCode({ isShow: true, message: "Missing data!" })
            return
        }
        if (signUpValue.password != signUpValue.repeatPassword) {
            seterrorCode({ isShow: true, message: "Passwords do not match!" })
            return
        }
        axios.post('auth/signup', { username: signUpValue.userName, email: signUpValue.email, password: signUpValue.password, repeat_password: signUpValue.repeatPassword })
            .then(res => {
                navigate("/signin")
            })
            .catch(err => {
                seterrorCode({ isShow: true, message: err.response.data.message })
            })
    }

    return (
        <section className="bg-gray-50 dark:bg-gray-900">
            <div className="flex flex-col items-center justify-center mx-auto md:h-screen lg:py-0">
                <Link to="/" className="flex items-center mb-6 text-2xl font-semibold text-gray-900">
                    <img className="w-8 h-8 mr-2" src="https://flowbite.s3.amazonaws.com/blocks/marketing-ui/logo.svg" />
                    Minimog
                </Link>
                <div className="w-full bg-white rounded-lg shadow dark:border md:mt-0 sm:max-w-md xl:p-0 dark:bg-gray-800 dark:border-gray-700">
                    <div className="p-6 space-y-4 md:space-y-6 sm:p-8">
                        <div className="space-y-4 md:space-y-6" >
                            <div>
                                <label className="block mb-2 text-sm font-medium text-gray-900 dark:text-white">Username</label>
                                <input type="text" name="userName" onChange={onChangeSignUpValue} className="bg-gray-50 border border-gray-300 text-gray-900 sm:text-sm rounded-lg focus:ring-primary-600 focus:border-primary-600 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500" />
                            </div>
                            <div>
                                <label className="block mb-2 text-sm font-medium text-gray-900 dark:text-white">Email</label>
                                <input type="email" name="email" onChange={onChangeSignUpValue} className="bg-gray-50 border border-gray-300 text-gray-900 sm:text-sm rounded-lg focus:ring-primary-600 focus:border-primary-600 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500" />
                            </div>
                            <div>
                                <label className="block mb-2 text-sm font-medium text-gray-900 dark:text-white">Password</label>
                                <input type="password" name="password" onChange={onChangeSignUpValue} className="bg-gray-50 border border-gray-300 text-gray-900 sm:text-sm rounded-lg focus:ring-primary-600 focus:border-primary-600 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500" />
                            </div>
                            <div>
                                <label className="block mb-2 text-sm font-medium text-gray-900 dark:text-white">Repeat password</label>
                                <input type="password" name="repeatPassword" onChange={onChangeSignUpValue} className="bg-gray-50 border border-gray-300 text-gray-900 sm:text-sm rounded-lg focus:ring-primary-600 focus:border-primary-600 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500" />
                            </div>
                            {errorCode.isShow &&
                                <div className="px-2 py-1 text-sm text-red-700 bg-red-100 rounded-lg dark:bg-red-200 dark:text-red-800" role="alert">
                                    <span className="font-medium">{errorCode.message}</span>
                                </div>
                            }
                            <button onClick={handleSignUp} className="w-full text-red-500 border border-red-500 hover:bg-red-500 hover:text-white active:bg-red-600 font-bold px-3 py-1 rounded outline-none focus:outline-none ease-linear transition-all duration-150">
                                Sign Up
                            </button>
                            <p className="text-sm font-light text-gray-500 dark:text-gray-400">
                                Already have an account? <Link to="/signin" className="font-medium text-primary-600 hover:underline dark:text-primary-500">Sign In</Link>
                            </p>
                        </div>
                    </div>
                </div>
            </div>
        </section>
    )
}

export default Index