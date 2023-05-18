import { useState } from 'react'

import { HiMinusSm } from 'react-icons/hi'
import { IoMdAdd } from 'react-icons/io'

import { useSelector, useDispatch } from 'react-redux'
import { Link } from 'react-router-dom'
import { remove, upAmount, downAmount } from '../../../features/cart/cartSlice'

const CartItem = ({ data }) => {

    const dispatch = useDispatch()

    const removeItem = (id) => {
        dispatch(remove(id))
    }

    const handleDown = (id) => {
        dispatch(downAmount(id))
    }

    const handleUp = (id) => {
        dispatch(upAmount(id))
    }
    return (
        <div className="flex items-center mb-2">
            <Link to={`/product/${data.data.data.id}`} state={data.data.data}>
                <img className="w-24" src={data.data.data.image[0]} />
            </Link>
            <div className="pl-4">
                <Link to={`/product/${data.data.data.id}`} state={data.data.data}>
                    <p className="font-medium hover:underline">{data.data.data.name}</p>
                </Link>
                <p className=""><span className="font-medium">Color: </span>{data.data.data.colors[0]}</p>
                <p className="">${data.data.data.price}.00</p>
                <div className="flex items-center mt-2.5">
                    <div className="flex items-center overflow-hidden rounded bg-slate-200">
                        <button onClick={() => handleDown(data.data.data.id)} className="p-2" >
                            <HiMinusSm />
                        </button>
                        <p className="w-4">{data.data.amount}</p>
                        <button onClick={() => handleUp(data.data.data.id)} className="p-2" >
                            <IoMdAdd />
                        </button>
                    </div>
                    <button onClick={() => removeItem(data.data.data.id)} className="opacity-80 text-sm underline p-2 ml-2">Remove</button>
                </div>
            </div>
        </div>
    )
}

export default CartItem