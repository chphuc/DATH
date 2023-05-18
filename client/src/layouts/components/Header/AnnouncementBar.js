import { useState } from 'react'

import { IoMdClose } from "react-icons/io";

const AnnouncementBar = () => {

    const [isShow, setIsShow] = useState(true)

    return (
        <>
            {isShow &&
                <div onClick={() => setIsShow(false)} className="flex items-center bg-red-600 py-2 px-2" >
                    <p className="grow text-center text-white text-sm font-medium">Free Delivery on orders over £120. Don’t miss discount.</p>
                    <IoMdClose className="text-white text-lg cursor-pointer" />
                </div >
            }
        </>
    )
}

export default AnnouncementBar