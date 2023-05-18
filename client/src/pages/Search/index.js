import { BiSearch } from 'react-icons/bi'
import ProducsItem from '../Products/ProductsItem'
import { useEffect, useRef, useState } from 'react'
import { BiChevronsRight } from "react-icons/bi";
import { BiChevronsLeft } from "react-icons/bi";
import { Link, useLocation } from 'react-router-dom';
import { Navigate } from 'react-router-dom';
import axios from 'axios'

const Index = (props) => {
    const inputValue = useRef("");

    let location = useLocation();
    let keywork = location.search.split('=')[1];
    if (keywork.includes("%20")) {
        keywork = keywork.replaceAll("%20", " ");
    }
    let api = `http://localhost:8080/api/search/items?keyword=${keywork}`;
    let [data, setData] = useState([]);

    useEffect(() => {
        axios
            .get(api)
            .then(res => setData(res.data))
            .catch(err => console.log(''))
    }, [location.search])



    let setKeyWord = (value) => {
        window.location.search = `?keyword=${value}`;
    }

    const [currentPage, setCurrentPage] = useState(1);
    const handlePage = (pageNext) => {
        setCurrentPage(pageNext);
        window.scrollTo(0, 0);
    }

    const quantity = 12;
    const maxPage = data.length / quantity
    const lastIndex = currentPage * quantity;
    const firstIndex = lastIndex - quantity;
    const currentData = data.slice(firstIndex, lastIndex);
    let numberOfPage = [];

    for (var i = 0; i < maxPage; i++) {
        numberOfPage.push(i + 1);
    }


    return (
        <>  {keywork != ""
            ? <>

                <div class="text-center">
                    <h1 class="text-4xl mt-20 mb-7">Found {data.length}  results for "{keywork}"</h1>
                    <div class="w-31/100 h-11 relative  m-auto">
                        <input class="w-full h-full p-4 outline-0 border rounded focus:border-black" type="text" placeholder="Search products" ref={inputValue}></input>
                        <button class="absolute mt-3 px-4 right-0  text-xl " onClick={() => setKeyWord(inputValue.current.value)}>
                            <BiSearch />
                        </button>
                    </div>
                </div>
                {data.length != 0
                    ? <div><div class=" mt-[110px]" >
                        <div class="w-78/100  m-auto">
                            <div class="grid grid-cols-4 gap-x-6 gap-y-90 ">
                                {currentData.map((item, index) => (

                                    <ProducsItem item={item} />
                                )
                                )
                                }
                            </div>

                        </div>
                    </div>
                        {numberOfPage.length > 1
                            ? <div class="switchPage flex w-[225px] justify-between mt-[85px] m-auto mb-[115px]">
                                <button class="flex flex-none w-[40px] h-[40px] justify-center items-center hover:bg-gray-100 hover:boder hover:rounded-full hover:cursor-pointer transition ease-in-out" onClick={() => handlePage(currentPage - 1)} disabled={currentPage < 2 ? true : false}><BiChevronsLeft /></button>
                                {numberOfPage.map((numPage) => (
                                    <>
                                        {numPage !== currentPage ? <div class="flex flex-none w-[40px] h-[40px] justify-center items-center hover:bg-gray-100 hover:boder hover:rounded-full hover:cursor-pointer transition ease-in-out" onClick={() => handlePage(numPage)}>{numPage}</div> : <div class="flex flex-none w-[45px] h-[45px] justify-center items-center bg-gray-100 boder rounded-full cusor:default " onClick={() => handlePage(numPage)}>{numPage}</div>
                                        }
                                    </>
                                )
                                )}
                                <button class="flex flex-none w-[40px] h-[40px] justify-center items-center hover:bg-gray-100 hover:boder hover:rounded-full hover:cursor-pointer transition ease-in-out" onClick={() => handlePage(currentPage + 1)} disabled={currentPage >= maxPage ? true : false}><BiChevronsRight /></button>
                            </div>
                            : <div class="switchPage flex w-[225px] justify-between mt-[85px] m-auto mb-[115px]"></div>
                        }
                    </div>
                    : <div class="text-center mt-[125px] mb-[120px]">
                        <p class="text-xl">Please try a different search term or go back to the <span class="underline decoration-solid cursor-pointer"><Link to="/">homepage </Link></span>.</p>
                    </div>
                }
            </>
            : <>
                <div class="text-center  mb-[120px]">
                    <h1 class="text-4xl mt-20 mb-7">Search our store</h1>
                    <div class="w-31/100 h-11 relative  m-auto">
                        <input class="w-full h-full p-4 outline-0 border rounded focus:border-black" type="text" placeholder="Search products" ref={inputValue}></input>
                        <button class="absolute mt-3 px-4 right-0  text-xl " onClick={() => setKeyWord(inputValue.current.value)}>
                            <BiSearch />
                        </button>
                    </div>
                </div>
            </>
        }
        </>
    )
}

export default Index;