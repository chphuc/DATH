import { useState, useEffect } from 'react'

import { AiOutlineShoppingCart } from 'react-icons/ai';
import { MdKeyboardArrowUp } from 'react-icons/md';
import { MdKeyboardArrowDown } from 'react-icons/md';

import { useSelector, useDispatch } from 'react-redux'

const CheckOutSummaryItem = () => {

    const [showOrderSummary, setShoowOrderSummary] = useState(true)
    const [data, setData] = useState(useSelector(state => state.cart.cart))
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
        <div className="lg:px-10">
            <div className="lg:hidden" onClick={() => setShoowOrderSummary(prev => !prev)}>
                <div className="py-3 border-y flex items-center justify-between">
                    <div className="flex items-center text-sky-800">
                        <span className="text-lg">
                            <AiOutlineShoppingCart />
                        </span>
                        <p className="mx-2">Show order summary</p>
                        <span className="text-lg">
                            {showOrderSummary ? <MdKeyboardArrowUp /> : <MdKeyboardArrowDown />}
                        </span>
                    </div>
                    <p className="font-medium text-lg text-green-600">${total}.00</p>
                </div>
            </div>
            {showOrderSummary &&
                <>
                    <div className="w-full h-96 pt-3 pr-3 overflow-y-auto scroll1">
                        {data.map((item, index) => (
                            <div key={index} className="flex items-center font-medium mb-3">
                                <div className="relative">
                                    <img className="w-16 rounded" src={item.data.data.image[0]} />
                                    <span className="absolute -top-2 -right-2 flex items-center justify-center text-white text-xs w-5 h-5 rounded-full bg-slate-500"><span>{item.data.amount}</span></span>
                                </div>
                                <p className="flex-1 px-4">{item.data.data.name}</p>
                                <p>${item.data.data.price}.00</p>
                            </div>
                        ))}
                    </div>

                    <div className="py-3 my-4 border-y">
                        <div className="mb-2 flex items-center justify-between">
                            <p className="text-gray-700">Subtotal</p>
                            <p className="font-medium">${total}.00</p>
                        </div>
                        <div className="flex items-center justify-between">
                            <p className="text-gray-700">Shipping</p>
                            <p className="font-medium">Free</p>
                        </div>
                    </div>
                    <div className="lg:mb-4 flex items-center justify-between font-medium">
                        <p className="text-xl">Total</p>
                        <p className="text-2xl text-green-600">${total}.00</p>
                    </div>
                </>
            }
        </div>
    )
}

export default CheckOutSummaryItem