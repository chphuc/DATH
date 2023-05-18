import { useState } from 'react'
import { Link } from 'react-router-dom'

import { AiOutlineStar } from 'react-icons/ai';
import { RiShoppingBagLine } from 'react-icons/ri'
import { AiOutlineEye } from 'react-icons/ai';
import { TbArrowsDownUp } from 'react-icons/tb';

import { useSelector, useDispatch } from 'react-redux'
import { add } from '../../features/cart/cartSlice'

import { toast } from 'react-toastify';

const HomeBestSellerItem = ({ data }) => {

    const notifySuccessAddItem = () => toast.success('Add success!', {
        position: "top-right",
        autoClose: 1000,
        hideProgressBar: false,
        closeOnClick: true,
        pauseOnHover: true,
        draggable: true,
        progress: undefined,
        theme: "light",
    });

    const dispatch = useDispatch()

    const [colorCur, setColorCur] = useState(0)
    const [isHoverCard, setIsHoverCard] = useState(false);
    const [isHoverImage, setIsHoverImage] = useState(false);

    const addCart = (data) => {
        dispatch(add(data))
        notifySuccessAddItem()
    }
    return (
        <div>
            <div className={"cursor-pointer md:px-4 pb-10 transition duration-200 " + (isHoverCard ? "shadow-lg" : "shadow-none	")} onMouseEnter={() => setIsHoverCard(true)} onMouseLeave={() => setIsHoverCard(false)}>
                <div className="relative">
                    <div className="overflow-hidden relative" onMouseEnter={() => setIsHoverImage(true)} onMouseLeave={() => setIsHoverImage(false)}>
                        {/* Cart Image */}
                        <Link to={`/product/${data.id}`} state={data}>
                            <div>
                                {/* Cart Image Main*/}
                                <div>
                                    <img className="w-64" src={data.image[0]} />
                                </div>
                                {/* Cart Image Hover*/}
                                <div>
                                    <img className={"w-64 absolute top-0 left-0 z-10 transition duration-700 " + (isHoverImage ? "opacity-100" : "opacity-0")} src={data.image[1] || data.image[0]} />
                                </div>
                            </div>
                        </Link>
                        {/* Card Action */}
                        <div className={"hidden md:block w-full px-2 absolute -bottom-12 left-0 transition duration-200 z-20 " + (isHoverCard ? "-translate-y-16" : "")}>
                            <button onClick={() => addCart({ data, amount: 1 })} className={"w-full shadow-md font-medium rounded p-2 bg-white hover:bg-black hover:text-white transition duration-200 "}>
                                Add to cart
                            </button>
                        </div>
                    </div>
                </div>
                <Link to={`/product/${data.id}`} state={data}>
                    <div className="mt-3">
                        <p className="font-medium mb-1">{data.name}</p>
                        <p className="">${data.price}.00</p>
                        <div className="mt-3 flex items-center flex-wrap">
                            {data.colors.map((item, index) => {
                                if (colorCur == index)
                                    return (
                                        <div key={index} onClick={() => setColorCur(index)} className={"w-6 h-6 rounded-full border border-black flex items-center justify-center " + (index != 0 ? "ml-2" : "")}>
                                            <div style={{ backgroundColor: `${item}` }} className="w-4 h-4 rounded-full">
                                            </div>
                                        </div>
                                    )
                                else
                                    return (
                                        <div onClick={() => setColorCur(index)} key={index} style={{ backgroundColor: `${item}` }} className={"w-6 h-6 rounded-full " + (index != 0 ? "ml-2" : "")}></div>
                                    )
                            })}
                        </div>
                    </div>
                </Link>
                <div>
                </div>
            </div>
        </div>
    )
}

export default HomeBestSellerItem