import { useState, useEffect } from 'react'
import { Link, useNavigate } from "react-router-dom";
import { useSelector, useDispatch } from 'react-redux'
import { signOut } from '../../../features/user/userSlice'
import { resetCart } from '../../../features/cart/cartSlice'

import AnnouncementBar from './AnnouncementBar'
import Navbar from './Navbar'
import Search from './Search'
import Cart from './Cart'

import Tippy from '@tippyjs/react'
import 'tippy.js/dist/tippy.css'

import { BiSearch } from 'react-icons/bi'
import { VscSignOut } from 'react-icons/vsc'
import { RiShoppingBagLine } from 'react-icons/ri'

const Header = () => {
    const dispatch = useDispatch()
    const navigate = useNavigate()
    const user = useSelector(state => state.user)

    const [showSearch, setShowSearch] = useState(false)
    const [showCart, setShowCart] = useState(false)

    let itemsLength = useSelector(state => state.cart.cart).length
    const [cartLength, setCartLength] = useState(0)

    const openSearch = () => {
        setShowSearch(true)
    }

    const onClickCart = () => {
        setShowCart(true)
    }

    const handleSignout = () => {
        dispatch(signOut())
        dispatch(resetCart())
        navigate("/")
    }

    useEffect(() => {
        setCartLength(itemsLength)
    }, [itemsLength])

    return (
        <>
            <AnnouncementBar />
            <div className="flex items-center px-4 lg:px-12 py-3 shadow">
                <div className="flex-1 flex items-center">
                    <Navbar />
                </div>
                <div className="w-36">
                    <a href="/">
                        <img src="https://cdn.shopify.com/s/files/1/0591/1350/4958/files/3.png?v=1628328728&width=360" />
                    </a>
                </div>
                <div className="flex-1 flex items-center justify-end">
                    {
                        user.user
                            ?
                            <>
                                <Tippy content="Search">
                                    <div className="cursor-pointer px-2 lg:px-3" onClick={openSearch}>
                                        <BiSearch className="text-xl" />
                                    </div>
                                </Tippy>
                                {showSearch &&
                                    <Search setShowSearch={setShowSearch} />
                                }
                                {/* ---------------------------------------------------------------- */}
                                <Tippy content="Cart">
                                    <div className="relative cursor-pointer px-2 lg:px-3" onClick={onClickCart}>
                                        <RiShoppingBagLine className="text-xl" />
                                        <div className="inline-flex absolute -top-2 -right-1 justify-center items-center w-5 h-5 text-xs font-bold text-white bg-red-500 rounded-full border-1 border-white dark:border-gray-900">
                                            {cartLength}
                                        </div>
                                    </div>
                                </Tippy>
                                {showCart &&
                                    <Cart setShowCart={setShowCart} />
                                }
                                {/* ---------------------------------------------------------------- */}
                                <Tippy content="Sign out">
                                    <div onClick={handleSignout} className="hidden lg:flex cursor-pointer px-2 lg:px-3">
                                        <VscSignOut className="text-xl" />
                                    </div>
                                </Tippy>
                            </>
                            :
                            <Link to="/signin">
                                <button className="text-gray-900 hover:text-white border border-gray-800 hover:bg-gray-900 focus:ring-4 focus:outline-none focus:ring-gray-300 font-medium rounded-lg text-sm px-5 py-1.5 text-center mr-2 mb-2 dark:border-gray-600 dark:text-gray-400 dark:hover:text-white dark:hover:bg-gray-600 dark:focus:ring-gray-800">Sign in</button>
                            </Link>
                    }
                </div>
            </div>
        </>
    )
}

export default Header