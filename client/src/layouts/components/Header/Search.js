import { useState, useEffect } from 'react'

import OutsideAlerter from '../../../components/OutsideAlerter'
import { Link } from 'react-router-dom'
import { IoMdClose } from 'react-icons/io'
import { BiSearch } from 'react-icons/bi'
import axios from 'axios'

import ProducsItem from '../../../pages/Products/ProductsItem'

const Search = ({ setShowSearch }) => {

    const [searchStyle, setSearchStyle] = useState("-translate-y-full")
    const [inputSearch, setInputSearch] = useState("")
    const [resultsSearch, setResult] = useState([]);

    const closeSearch = () => {
        setSearchStyle("-translate-y-full")

        setTimeout(() => {
            setShowSearch(false)
        }, 300);
    }

    useEffect(() => {
        setSearchStyle("translate-y-0")
    }, [])

    useEffect(() => {
        let api = `http://localhost:8080/api/search/items?keyword=${inputSearch}`
        axios
            .get(api)
            .then(res => setResult(res.data))
            .catch(err => console.log('err: ', err));

    }, [inputSearch])

    return (
        <div className="flex fixed top-0 right-0 w-full h-screen bg-black bg-opacity-30 z-50">
            <OutsideAlerter todo={closeSearch} compStyle={"relative w-full h-full h-full lg:h-fit bg-white px-4 lg:px-12 py-4 md:py-8 transition duration-300 " + searchStyle}>
                {/* <div className="flex justify-between items-center md:hidden mb-2">
                    <h3 className="text-base font-medium">Search our store</h3>
                    <button className="text-black p-2 text-xl" onClick={closeSearch}>
                        <IoMdClose />
                    </button>
                </div> */}
                <div className="flex justify-center">
                    <div className="w-full md:w-2/3 flex justify-center items-center">
                        <div className="relative w-full md:mx-28 flex border border-black rounded">
                            <input
                                type="text"
                                className="w-full h-11 outline-none px-4"
                                placeholder="Search products"
                                value={inputSearch}
                                onChange={(e) => setInputSearch(e.target.value)}
                            />
                            <button className="absolute top-px right-0 py-3 px-3.5 text-xl" onClick={closeSearch}>
                                <Link to={`/search?query=${inputSearch}`}> <BiSearch /> </Link>
                            </button>
                        </div>
                    </div>
                </div>
                {!inputSearch
                    ?
                    <div className="flex md:justify-center mt-3 flex-wrap">
                        <span className="text-[#666] mr-4">Popular Searches:</span>
                        <div className="flex items-center flex-wrap">
                            <button onClick={closeSearch}><Link to={"/search?query=T-Shirt"} className="cursor-pointer underline mr-4 hover:text-gray-800 whitespace-nowrap">T-Shirt</Link></button>
                            <button onClick={closeSearch}><Link to={"/search?query=Dress"} className="cursor-pointer underline mr-4 hover:text-gray-800 whitespace-nowrap">Dress</Link></button>
                            <button onClick={closeSearch}><Link to={"/search?query=Jacket"} className="cursor-pointer underline mr-4 hover:text-gray-800 whitespace-nowrap">Jacket</Link></button>
                        </div>
                    </div>
                    :
                    <div className="">
                        <p className="mt-9 mb-7 text-center text-2xl text-slate-400">Results for "<span className="text-black">{inputSearch}</span>"</p>
                        <div className="grid grid-cols-2 lg:grid-cols-6 gap-2 overflow-y-auto no-scroll heightCart">
                            {resultsSearch.map((item, index) => (
                                <div key={index}>
                                    <button class="w-48" onClick={closeSearch}>   <ProducsItem item={item} /> </button>
                                </div>
                            ))}
                        </div>
                    </div>
                }
            </OutsideAlerter>
        </div>
    )
}

export default Search