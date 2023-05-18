import { TbMinusVertical } from 'react-icons/tb';
import { FaFacebookF } from 'react-icons/fa';
import { FaInstagram } from 'react-icons/fa';

const TopNavbar = () => {
    return (
        <div className="hidden lg:grid grid-cols-3 py-2 px-12 border-b">
            <div className="flex items-center">
                <div className="flex items-center hover:text-gray-500 cursor-pointer mr-4">
                    <FaFacebookF />
                    <p className="px-2">300k Followers</p>
                </div>
                <div className="flex items-center hover:text-gray-500 cursor-pointer">
                    <FaInstagram />
                    <p className="px-2">100k Followers</p>
                </div>
            </div>
            <div className="flex items-center justify-center">
                <p className="">Open Doors To A World Of Fashion</p>
                <TbMinusVertical className="text-xl" />
                <p className="underline hover:text-gray-500 cursor-pointer">Discover More</p>
            </div>
            <div className="flex justify-end">
                <select className="text-gray-900 text-sm font-medium rounded-lg block outline-none">
                    <option defaultValue value="EN">English</option>
                    <option value="CA">Canada</option>
                    <option value="DE">Germany</option>
                </select>
                <select className="text-gray-900 text-sm font-medium rounded-lg block outline-none">
                    <option defaultValue value="usd">USD</option>
                    <option value="eur">EUR</option>
                </select>
            </div>
        </div>
    )
}

export default TopNavbar