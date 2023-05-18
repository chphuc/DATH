import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'

import CartItem from './CartItem'
import OutsideAlerter from '../../../components/OutsideAlerter'

import { IoMdClose } from 'react-icons/io'

import { useSelector, useDispatch } from 'react-redux'

const Cart = ({ setShowCart }) => {

    const dispatch = useDispatch()

    const [cartStyle, setCartStyle] = useState("translate-x-full")

    const closeCart = () => {
        setCartStyle("translate-x-full")

        setTimeout(() => {
            setShowCart(false)
        }, 300);
    }

    useEffect(() => {
        setCartStyle("translate-x-0")
    }, [])

    const [data, setData] = useState([])
    const [total, setTotal] = useState(0)

    let items = useSelector(state => state.cart.cart)
    const InitData = () => {
        setData(items)
        let temp = 0
        items.forEach(item => temp += +item.data.data.price * +item.data.amount)
        setTotal(temp);
    }
    useEffect(() => {
        InitData()
    }, [items])

    return (
        <div className="flex justify-end fixed top-0 right-0 w-full h-full bg-black bg-opacity-30 z-50">
            <OutsideAlerter todo={closeCart} compStyle={"relative w-10/12 md:w-1/3 h-full bg-white px-3 lg:px-6 pt-6 pb-4 transition duration-300 " + cartStyle}>
                <div className="absolute top-0 right-0 text-2xl p-2 cursor-pointer" onClick={closeCart}>
                    <IoMdClose />
                </div>
                <div className="flex flex-col h-full">
                    <p className="text-2xl font-medium">Shopping Cart</p>
                    {!data.length ?
                        <p>Your cart is currently empty.</p>
                        :
                        <div className="flex flex-col h-full pt-3 pb-10">
                            <div className="flex-1 overflow-y-auto no-scroll md:scroll1">
                                {data.map((item, index) => (
                                    <CartItem key={index} data={item} />
                                ))}
                            </div>
                            <div className="">
                                <div className="flex items-center justify-between py-4">
                                    <p className="font-medium text-lg">Subtotal</p>
                                    <p className="font-medium text-lg">${total}.00</p>
                                </div>
                                <Link to="/checkout">
                                    <button onClick={closeCart} className="w-full py-2 px-7 font-medium border border-black rounded text-white bg-black hover:scale-105 transition duration-300">
                                        Check out
                                    </button>
                                </Link>
                            </div>
                        </div>
                    }
                </div>
            </OutsideAlerter>
        </div>
    )
}

export default Cart