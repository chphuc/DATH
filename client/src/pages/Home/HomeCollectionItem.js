import { useState } from 'react'
import { HiArrowRight } from 'react-icons/hi'

const HomeCollectionItem = ({ urlImage, title, amountItem }) => {

    const [isItemHover, setIsItemHover] = useState(false)

    const hoverItemEvent = () => {
        setIsItemHover(true)
    }
    const notHoverItemEvent = () => {
        setIsItemHover(false)
    }
    return (
        <div
            style={{
                width: '276px',
                height: '373px',
                backgroundImage: `url("${urlImage}")`,
                backgroundPosition: 'center',
                backgroundSize: 'cover'
            }}
            onMouseEnter={hoverItemEvent}
            onMouseLeave={notHoverItemEvent}
            className="flex flex-col justify-end cursor-pointer"
        >
            <div className="flex items-center justify-between px-7 py-5">
                <div>
                    <p className="text-black text-lg md:text-xl font-medium">{title}</p>
                    <p className="mt-4 text-color-subtext">{amountItem} items</p>
                </div>
                <div className={"relative w-11 h-11 " + (isItemHover ? "text-white" : "text-black")}>
                    <div className={"w-full h-full rounded-full hover:scale-110 transition duration-200 " + (isItemHover ? "bg-black" : "bg-white")}>
                    </div>
                    <button style={{ top: "50%", left: "50%", transform: "translate(-50%,-50%)" }} className="absolute z-10 pointer-events-none">
                        <HiArrowRight />
                    </button>
                </div>
            </div>
        </div>
    )
}

export default HomeCollectionItem